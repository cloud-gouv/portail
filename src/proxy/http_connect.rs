use crate::proxy::context::OwnedRequestContext;
use crate::proxy::protocol_detect::{ALPN_H2, ALPN_HTTP1_1};
use crate::{
    config::{BackendSettings, Settings},
    proxy::{ProxyError, client_tls},
    state::State,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::time::Instant;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// This is a workaround for the restriction `only auto traits can be used as additional traits in a trait object`
trait OutboundStreamIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> OutboundStreamIo for T {}

type OutboundStream = Box<dyn OutboundStreamIo + Send + Unpin>;

#[derive(Debug)]
enum InboundHttpProtocol {
    Http1,
    Http2,
}

/// References:
/// - https://docs.rs/hyper/latest/hyper/upgrade/index.html
/// - https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
/// - https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
pub async fn serve_http1_connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: OwnedRequestContext,
    stream: S,
) -> Result<(), ProxyError> {
    debug!("{}: HTTP/1.1 CONNECT request", ctx.client_address);
    let io = TokioIo::new(stream);

    // TODO: update ctx

    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                handle_http_request(
                    req,
                    ctx.clone(),
                    settings.clone(),
                    state.clone(),
                    InboundHttpProtocol::Http1,
                )
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| ProxyError::HTTPConnectError(e.to_string()))?;

    Ok(())
}

pub async fn serve_http2_connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: OwnedRequestContext,
    stream: S,
) -> Result<(), ProxyError> {
    debug!("{}: HTTP/2 CONNECT request", ctx.client_address);
    let io = TokioIo::new(stream);

    // TODO: update ctx
    //

    // TokioExecutor is a wrapper around tokio::spawn
    // https://docs.rs/hyper-util/latest/src/hyper_util/rt/tokio.rs.html#112
    http2::Builder::new(TokioExecutor::new())
        .enable_connect_protocol()
        .serve_connection(
            io,
            service_fn(move |req| {
                handle_http_request(
                    req,
                    ctx.clone(),
                    settings.clone(),
                    state.clone(),
                    InboundHttpProtocol::Http2,
                )
            }),
        )
        .await
        .map_err(|e| ProxyError::HTTPConnectError(e.to_string()))?;

    Ok(())
}

#[tracing::instrument(skip_all, fields(inbound_protocol, uri = %req.uri(), method = %req.method(), trace_id = %initial_ctx.trace_id, client_address = %initial_ctx.client_address))]
async fn handle_http_request(
    req: Request<Incoming>,
    initial_ctx: OwnedRequestContext,
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    inbound_protocol: InboundHttpProtocol,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut ctx = initial_ctx.as_local();
    let start = Instant::now();

    if req.method() != Method::CONNECT {
        debug!(
            "Unsupported HTTP method received, terminating connection",
        );
        // TODO: we might want to handle this case in the future
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    ctx.acl_ctx.insert(
        "proxy.protocol",
        crate::acl::ast::ConcreteOperand::String("http"),
    );

    let Some(target_authority) = req.uri().authority() else {
        debug!("Invalid authority in CONNECT URI, terminating connection");
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    };

    let target_address = target_authority.to_string();
    let mut final_address = target_address.clone();
    debug!(final_address = %final_address,
        "HTTP CONNECT request");
    let mut backends: Vec<&BackendSettings> = Vec::with_capacity(1);
    // We evaluate first whether we are allowed then we evaluate routes.
    let acl = &state.read().await.acl_rules;

    let default_port = match req.uri().scheme_str().unwrap_or("http") {
        "http" => 80,
        "https" => 443,
        _ => 80,
    };

    ctx.acl_ctx.insert(
        "host",
        crate::acl::ast::ConcreteOperand::String(target_authority.host()),
    );
    ctx.acl_ctx.insert(
        "port",
        crate::acl::ast::ConcreteOperand::Number(
            target_authority.port_u16().unwrap_or(default_port).into(),
        ),
    );
    ctx.acl_ctx.insert(
        "path",
        crate::acl::ast::ConcreteOperand::String(req.uri().path()),
    );
    ctx.acl_ctx.insert(
        "query",
        crate::acl::ast::ConcreteOperand::String(req.uri().query().unwrap_or_default()),
    );
    ctx.acl_ctx.insert(
        "method",
        crate::acl::ast::ConcreteOperand::String(req.method().as_str()),
    );
    ctx.acl_ctx.insert(
        "scheme",
        crate::acl::ast::ConcreteOperand::String(req.uri().scheme_str().unwrap_or("http")),
    );

    // TODO: how much header information should we render available?

    let mut recommended_routes = match ctx.acl_ctx.evaluate_routes(&acl.hir) {
        Ok(routes) => routes,
        Err(failure) => {
            let mut resp = Response::new(empty_body());
            warn!(
                "Failed to evaluate a request: {} (Context: {:#?})",
                failure, ctx
            );
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(resp);
        }
    };

    if !recommended_routes.is_empty() {
        backends.append(&mut recommended_routes);
    }

    if backends.is_empty()
        && let Some(ref backend_id) = state.read().await.default_backend
    {
        let backend = settings
            .backends
            .get(backend_id)
            .unwrap_or_else(|| panic!("BUG: default backend {backend_id} went away from settings"));

        backends.push(backend);
    }

    backends.reverse();

    if backends.is_empty() {
        ctx.acl_ctx.insert(
            "route.local",
            crate::acl::ast::ConcreteOperand::Boolean(true),
        );
    } else {
        ctx.acl_ctx.insert(
            "route.local",
            crate::acl::ast::ConcreteOperand::Boolean(false),
        );
    }

    let assessment = match ctx.acl_ctx.evaluate_request(&acl.hir) {
        Ok(assessment) => assessment,
        Err(failure) => {
            let mut resp = Response::new(empty_body());
            warn!(
                "Failed to evaluate a request: {} (Context: {:#?})",
                failure, ctx
            );
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(resp);
        }
    };

    match assessment.action {
        // FIXME: render the deny template if there's one.
        crate::acl::Action::Deny(_explain_template) => {
            info!(
                duration_us = start.elapsed().as_micros(),
                "Request denied by ACL",
            );
            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::FORBIDDEN;
            return Ok(resp);
        }
        crate::acl::Action::Redirect(target) => {
            info!(
                original_host = %target_authority.host(),
                redirected_to = %target,
                duration_us = start.elapsed().as_micros(),
                "Request redirected by ACL",
            );
            final_address = target.to_string();
        }

        _ => {}
    }

    info!(
        duration_us = start.elapsed().as_micros(),
        "Request allowed by ACL",
    );

    let mut stream: Option<OutboundStream> = None;
    let start = Instant::now();
    for backend in backends {
        debug!(
            address = %final_address,
            backend = ?backend,
            "Backend selected for HTTP CONNECT"
        );
        match connect_to_http_proxy_backend(
            backend,
            &final_address,
            state.clone(),
            &inbound_protocol,
        )
        .await
        {
            Ok(upstream) => {
                debug!(
                    address = %final_address,
                    backend = ?backend,
                    duration_ms = start.elapsed().as_millis(),
                    "Stream established to upstream backend"
                );

                stream = Some(upstream);
                break;
            }
            Err(err) => {
                debug!(
                    backend = ?backend,
                    duration_ms = start.elapsed().as_millis(),
                    "Backend failed for HTTP CONNECT: {}, trying next",
                    err
                );
            }
        }
    }
    if stream.is_none() {
        debug!(
            address = %final_address,
            duration_ms = start.elapsed().as_millis(),
            "No backend, establishing a direct connection to the target"
        );
        let start = Instant::now();
        match TcpStream::connect(&final_address).await {
            Ok(socket) => {
                debug!(
                    address = %final_address,
                    duration_ms = start.elapsed().as_millis(),
                    "Stream directly established to final address (local exit)"
                );
                stream = Some(Box::new(socket))
            },
            Err(e) => warn!(
                address = %final_address,
                duration_ms = start.elapsed().as_millis(),
                "Direct connection failed: {}",
                e),
        }
    }

    let Some(mut stream) = stream else {
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        return Ok(resp);
    };

    tokio::task::spawn(async move {
        let ctx = initial_ctx;
        let start = Instant::now();
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                match tokio::io::copy_bidirectional(&mut client, &mut *stream).await {
                    Err(e) => error!(trace_id = %ctx.trace_id, client_address = %ctx.client_address, duration_ms = start.elapsed().as_millis(), "CONNECT tunnel error: {}", e),
                    Ok((n_bytes_sent, n_bytes_recv)) => {
                        info!(
                            trace_id = %ctx.trace_id,
                            client_address = %ctx.client_address,
                            n_bytes_sent = %n_bytes_sent,
                            n_bytes_recv = %n_bytes_recv,
                            duration_ms = start.elapsed().as_millis(),
                            "CONNECT tunnel finished successfully"
                        );
                    }
                }
            }
            Err(e) => error!(trace_id = %ctx.trace_id, client_address = %ctx.client_address, "CONNECT upgrade error: {}", e),
        }
    });

    // Connection: keep-alive is
    // - the default for HTTP/1.1
    // - stripped by hyper for HTTP/2 https://github.com/hyperium/hyper/blob/e13e783927d429fc03038fe512eeb4d379cf1a70/src/proto/h2/mod.rs#L43
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::OK;

    Ok(resp)
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Send CONNECT and return the stream on 2xx response
/// Ref: https://github.com/hyperium/hyper/blob/master/examples/client.rs
///
/// When upstream uses TLS, ALPN is ordered by inbound protocol:
/// - Client HTTP/1.1 → [http/1.1, h2]
/// - Client HTTP/2 → [h2, http/1.1]
///
/// When upstream is plain TCP, HTTP/1.1 is used.
async fn connect_to_http_proxy_backend(
    backend: &BackendSettings,
    final_address: &str,
    state: Arc<RwLock<State>>,
    inbound_protocol: &InboundHttpProtocol,
) -> io::Result<OutboundStream> {
    let socket = TcpStream::connect(backend.target_address).await?;

    let (stream, use_http2): (OutboundStream, bool) = if backend.identity_aware {
        debug!(
            "Backend is identity-aware, establishing a TLS connection to {}",
            backend.target_address
        );
        let domain = backend.tls_server_name.clone();

        let alpn_protocols = match inbound_protocol {
            InboundHttpProtocol::Http1 => vec![ALPN_HTTP1_1.to_vec(), ALPN_H2.to_vec()],
            InboundHttpProtocol::Http2 => vec![ALPN_H2.to_vec(), ALPN_HTTP1_1.to_vec()],
        };
        let tls = client_tls::connect_using_tls_auth(socket, domain, state, alpn_protocols).await?;

        let use_http2 = match tls {
            tokio_rustls::TlsStream::Client(ref client) => client
                .get_ref()
                .1
                .alpn_protocol()
                .map(|p| p as &[u8] == ALPN_H2)
                .unwrap_or(false),
            _ => false,
        };

        (Box::new(tls), use_http2)
    } else {
        (Box::new(socket), false)
    };

    let io = TokioIo::new(stream);

    // The following points are important for choosing the current implementation of the CONNECT:
    // 1. hyper has optimized the way it parses headers:
    //    https://github.com/hyperium/hyper/blob/72ebcffb7d82cda15aa74507b2cc522ca2a7a94d/src/proto/h1/role.rs#L113
    // 2. hyper treats CONNECT as having no body, so it will not read more than the headers:
    //    https://github.com/hyperium/hyper/blob/72ebcffb7d82cda15aa74507b2cc522ca2a7a94d/src/proto/h1/role.rs#L1233
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(final_address)
        .header(header::HOST, final_address)
        .body(Empty::<Bytes>::new())
        .map_err(io::Error::other)?;

    if use_http2 {
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake(io)
            .await
            .map_err(io::Error::other)?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Cannot HTTP CONNECT to upstream: {}", e);
            }
        });

        let mut response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "HTTP proxy CONNECT failed with status {}",
                    response.status()
                ),
            ));
        }

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .map_err(io::Error::other)?;

        Ok(Box::new(TokioIo::new(upgraded)) as OutboundStream)
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake(io)
            .await
            .map_err(io::Error::other)?;
        // We must await the connection (and enable upgrades)
        // https://docs.rs/hyper/latest/hyper/client/conn/http1/struct.Builder.html#method.handshake
        tokio::spawn(async move {
            if let Err(e) = conn.with_upgrades().await {
                warn!("Cannot HTTP CONNECT to upstream: {}", e);
            }
        });

        let mut response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!(
                    "HTTP proxy CONNECT failed with status {}",
                    response.status()
                ),
            ));
        }

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .map_err(io::Error::other)?;

        Ok(Box::new(TokioIo::new(upgraded)))
    }
}
