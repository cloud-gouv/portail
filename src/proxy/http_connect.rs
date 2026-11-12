use crate::backend_routing;
use crate::backend_routing::ACLDecision;
use crate::backend_routing::BackendOutcome;
use crate::config::{BackendSettings, KnownBackend};
use crate::dns::happy_eyeballs_connect;
use crate::proxy::protocols::{ALPN_H2, ALPN_HTTP1_1};
use crate::proxy::{
    context::OwnedRequestContext,
    target::TargetAuthority,
    tunnel::{TunnelContext, TunnelProtocol, serve_passthrough},
};
use crate::{
    proxy::{ProxyError, ProxyRuntime, client_tls},
    state::State,
};
use bytes::Bytes;
use http::uri::Authority;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header,
    server::conn::{http1, http2},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::Instant;
use tracing::{Instrument, debug, error, info, warn};

/// This is a workaround for the restriction `only auto traits can be used as additional traits in a trait object`
trait OutboundStreamIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> OutboundStreamIo for T {}

type OutboundStream = Box<dyn OutboundStreamIo + Send + Unpin>;

#[derive(Debug, Clone, Copy)]
enum InboundHttpProtocol {
    Http1,
    Http2,
}

const CONNECT_DEFAULT_PORT: u16 = 443;

#[derive(Debug, thiserror::Error)]
enum ConnectTargetError {
    #[error("The CONNECT URI has no authority")]
    MissingAuthority,
    #[error("The CONNECT URI uses absolute form")]
    AbsoluteForm,
    #[error(transparent)]
    InvalidAuthority(#[from] crate::proxy::target::TargetAuthorityError),
}

/// The CONNECT target, both as the client wrote it and in canonical form.
///
/// The two differ on purpose: ACL evaluation and dialing use the canonical host, while logs and
/// the HTTP/2 `:authority` echo must show what the client asked for.
struct ConnectTarget {
    authority: Authority,
    target: TargetAuthority,
}

fn parse_connect_target(uri: &http::Uri) -> Result<ConnectTarget, ConnectTargetError> {
    if uri.scheme().is_some() {
        return Err(ConnectTargetError::AbsoluteForm);
    }

    let Some(authority) = uri.authority() else {
        return Err(ConnectTargetError::MissingAuthority);
    };

    let target = TargetAuthority::parse(authority, CONNECT_DEFAULT_PORT)
        .map_err(ConnectTargetError::from)?;

    Ok(ConnectTarget {
        authority: authority.clone(),
        target,
    })
}

enum Decision {
    TerminateWithResponse(Response<BoxBody<Bytes, hyper::Error>>),
    RedirectDestination(String),
    Continue,
}

fn map_acl_decision(
    decision: ACLDecision,
    start: Instant,
    target_authority: &Authority,
) -> Result<Decision, hyper::Error> {
    match decision {
        ACLDecision::InternalError => {
            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            Ok(Decision::TerminateWithResponse(resp))
        }
        ACLDecision::Deny => {
            info!(
                subsystem = "proxy_access",
                duration_us = start.elapsed().as_micros(),
                "Request denied by ACL",
            );
            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::FORBIDDEN;

            Ok(Decision::TerminateWithResponse(resp))
        }
        ACLDecision::Redirect(target) => {
            info!(
                subsystem = "proxy_access",
                original_host = %target_authority.host(),
                redirected_to = %target,
                duration_us = start.elapsed().as_micros(),
                "Request redirected by ACL",
            );
            Ok(Decision::RedirectDestination(target.to_string()))
        }

        ACLDecision::Allow => Ok(Decision::Continue),
    }
}

/// References:
/// - https://docs.rs/hyper/latest/hyper/upgrade/index.html
/// - https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
/// - https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
#[tracing::instrument(skip_all, fields(trace_id = %ctx.trace_id, client_address = %ctx.client_address, subsystem = "proxy_access"))]
pub async fn serve_http1_connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    rt: Arc<ProxyRuntime>,
    ctx: OwnedRequestContext,
    stream: S,
) -> Result<(), ProxyError> {
    debug!(subsystem = "proxy_access", "HTTP/1.1 CONNECT request");
    let io = TokioIo::new(stream);

    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                handle_http_request(req, ctx.clone(), rt.clone(), InboundHttpProtocol::Http1)
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| ProxyError::HTTPConnectError(e.to_string()))?;

    Ok(())
}

#[tracing::instrument(skip_all, fields(trace_id = %ctx.trace_id, client_address = %ctx.client_address, subsystem = "proxy_access"))]
pub async fn serve_http2_connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    rt: Arc<ProxyRuntime>,
    ctx: OwnedRequestContext,
    stream: S,
) -> Result<(), ProxyError> {
    debug!(subsystem = "proxy_access", "HTTP/2 CONNECT request");
    let io = TokioIo::new(stream);

    // TokioExecutor is a wrapper around tokio::spawn
    // https://docs.rs/hyper-util/latest/src/hyper_util/rt/tokio.rs.html#112
    http2::Builder::new(TokioExecutor::new())
        .enable_connect_protocol()
        .serve_connection(
            io,
            service_fn(move |req| {
                handle_http_request(req, ctx.clone(), rt.clone(), InboundHttpProtocol::Http2)
            }),
        )
        .await
        .map_err(|e| ProxyError::HTTPConnectError(e.to_string()))?;

    Ok(())
}

#[tracing::instrument(skip_all, fields(inbound_protocol, uri = %req.uri(), method = %req.method(), trace_id = %initial_ctx.trace_id, client_address = %initial_ctx.client_address, subsystem = "proxy_access"))]
async fn handle_http_request(
    req: Request<Incoming>,
    initial_ctx: OwnedRequestContext,
    rt: Arc<ProxyRuntime>,
    inbound_protocol: InboundHttpProtocol,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    let mut ctx = initial_ctx.as_local();
    let start = Instant::now();

    if req.method() != Method::CONNECT {
        debug!(
            subsystem = "proxy_errors",
            "Unsupported HTTP method received, terminating connection",
        );
        // TODO: we might want to handle this case in the future
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    ctx.acl_ctx.insert(
        "http.version",
        crate::acl::ast::ConcreteOperand::String(match inbound_protocol {
            InboundHttpProtocol::Http1 => "h1.1",
            InboundHttpProtocol::Http2 => "h2",
        }),
    );

    ctx.acl_ctx.insert(
        "proxy.protocol",
        crate::acl::ast::ConcreteOperand::String("http"),
    );
    ctx.acl_ctx.insert(
        "tunnel.protocol",
        crate::acl::ast::ConcreteOperand::String("http"),
    );

    // CONNECT targets must use authority form. Absolute form lets the client control the
    // scheme, path, and query that the ACL sees.
    let ConnectTarget { authority, target } = match parse_connect_target(req.uri()) {
        Ok(target) => target,
        Err(error) => {
            error!(
                subsystem = "proxy_errors",
                uri = %req.uri(),
                "Rejected CONNECT target: {error}"
            );

            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::BAD_REQUEST;
            return Ok(resp);
        }
    };

    let port = target.port;
    let mut final_address = target.to_string();

    debug!(subsystem = "proxy_access", final_address = %final_address,
        "HTTP CONNECT request");

    ctx.acl_ctx.insert(
        "host",
        crate::acl::ast::ConcreteOperand::String(target.host.as_str()),
    );
    ctx.acl_ctx.insert(
        "tunnel.host",
        crate::acl::ast::ConcreteOperand::String(target.host.as_str()),
    );

    ctx.acl_ctx.insert(
        "port",
        crate::acl::ast::ConcreteOperand::Number(port.into()),
    );
    ctx.acl_ctx.insert(
        "tunnel.port",
        crate::acl::ast::ConcreteOperand::Number(port.into()),
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

    let (mut backends, acl) = match backend_routing::build_backend_chain(&rt, &mut ctx).await {
        (Some(b), acl) => (b, acl),
        (None, _) => {
            let mut resp = Response::new(empty_body());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(resp);
        }
    };
    match map_acl_decision(
        backend_routing::assess_request(&ctx, &acl),
        start,
        &authority,
    )? {
        Decision::TerminateWithResponse(resp) => return Ok(resp),
        Decision::RedirectDestination(target) => final_address = target,
        Decision::Continue => {}
    }

    info!(
        subsystem = "proxy_access",
        duration_us = start.elapsed().as_micros(),
        "Request allowed by ACL",
    );

    let mut stream = match connect_to_http_backends(
        &rt,
        &mut backends,
        &final_address,
        inbound_protocol,
    )
    .await
    {
        Some(Ok(upstream)) => Some(upstream),
        Some(Err(resp)) => return Ok(resp),
        None => None,
    };

    if stream.is_none() {
        // At this point, we need to re-assess if the request can go through.
        backend_routing::mark_direct_exit(&mut ctx);

        match map_acl_decision(
            backend_routing::assess_request(&ctx, &acl),
            start,
            &authority,
        )? {
            Decision::TerminateWithResponse(resp) => return Ok(resp),
            Decision::RedirectDestination(target) => final_address = target,
            _ => {}
        }

        info!(
            subsystem = "proxy_access",
            duration_us = start.elapsed().as_micros(),
            "Request allowed by ACL (direct exit context)",
        );

        debug!(
            subsystem = "proxy_access",
            address = %final_address,
            duration_ms = start.elapsed().as_millis(),
            "No backend, establishing a direct connection to the target"
        );

        let start = Instant::now();
        let authority: Authority = match final_address.parse() {
            Ok(authority) => authority,
            Err(_) => {
                warn!(
                    subsystem = "proxy_errors",
                    address = %final_address,
                    duration_ms = start.elapsed().as_millis(),
                    "Direct connection target is an invalid authority",
                );
                let mut resp = Response::new(empty_body());
                *resp.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(resp);
            }
        };

        match happy_eyeballs_connect(
            &rt.dns,
            authority.host(),
            port,
            rt.settings.connect_timeout,
            rt.settings.tcp_nodelay,
        )
        .await
        {
            Ok((socket, resolved_target)) => {
                info!(
                    subsystem = "proxy_access",
                    address = %final_address,
                    resolved_target = %resolved_target,
                    duration_ms = start.elapsed().as_millis(),
                    "Stream directly established to final address via Happy Eyeballs (local exit)"
                );
                stream = Some(Box::new(socket))
            }
            Err(err) => warn!(
                subsystem = "proxy_errors",
                address = %final_address,
                duration_ms = start.elapsed().as_millis(),
                configured_timeout_ms = rt.settings.connect_timeout.as_millis(),
                "Direct connection via Happy Eyeballs failed: {err}",
            ),
        }
    }

    let Some(stream) = stream else {
        warn!(
            subsystem = "proxy_errors",
            address = %final_address,
            "No outbound stream could be established"
        );

        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        return Ok(resp);
    };

    let tunnel_ctx = TunnelContext::new(
        initial_ctx.trace_id,
        initial_ctx.client_address,
        target.clone(),
        initial_ctx.client_transport,
        TunnelProtocol::Http,
    );

    spawn_tunnel(req, tunnel_ctx, stream);

    // Connection: keep-alive is
    // - the default for HTTP/1.1
    // - stripped by hyper for HTTP/2 https://github.com/hyperium/hyper/blob/e13e783927d429fc03038fe512eeb4d379cf1a70/src/proto/h2/mod.rs#L43
    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::OK;

    Ok(resp)
}

async fn connect_to_http_backends(
    rt: &Arc<ProxyRuntime>,
    backends: &mut Vec<BackendSettings>,
    final_address: &str,
    inbound_protocol: InboundHttpProtocol,
) -> Option<Result<OutboundStream, Response<BoxBody<Bytes, hyper::Error>>>> {
    let start = Instant::now();

    let backend_result = backend_routing::try_backends(
        backends,
        final_address,
        rt.settings.connect_timeout,
        |backend, target| {
            let state = rt.state.clone();
            async move {
                match connect_to_http_proxy_backend(
                    &backend,
                    &target,
                    state,
                    inbound_protocol,
                )
                .await
                {
                    Ok(upstream) => {
                        info!(
                            subsystem = "proxy_access",
                            address = %target,
                            backend = ?backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Stream established to upstream backend"
                        );

                        BackendOutcome::Success(upstream)
                    }
                    Err(UpstreamConnectError::UpstreamResponse(resp)) => {
                        // Send back the client errors.
                        if resp.status().is_client_error() {
                            info!(
                                subsystem = "proxy_access",
                                backend = ?backend,
                                duration_ms = start.elapsed().as_millis(),
                                status = %resp.status(),
                                "Backend returned a non-200 client error for HTTP CONNECT, returning it to the client and terminating the request"
                            );

                            BackendOutcome::Fatal(resp.map(|b| b.boxed()))
                        } else {
                            info!(
                                subsystem = "proxy_access",
                                backend = ?backend,
                                duration_ms = start.elapsed().as_millis(),
                                status = %resp.status(),
                                "Backend returned a non-200 response for HTTP CONNECT, trying next as it's not a client error"
                            );

                            BackendOutcome::Retry
                        }
                    }
                    Err(UpstreamConnectError::IO(err)) => {
                        info!(
                            subsystem = "proxy_access",
                            backend = ?backend,
                            duration_ms = start.elapsed().as_millis(),
                            "Backend failed for HTTP CONNECT: {}, trying next",
                            err
                        );

                        BackendOutcome::Retry
                    }
                }
            }
        }).await;

    match backend_result {
        Some(Ok((upstream, _backend))) => Some(Ok(upstream)),
        Some(Err(resp)) => Some(Err(resp)),
        None => None,
    }
}

fn spawn_tunnel(req: Request<Incoming>, tunnel_ctx: TunnelContext, stream: OutboundStream) {
    tokio::task::spawn(
        async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let client = TokioIo::new(upgraded);
                    if let Err(error) = serve_passthrough(&tunnel_ctx, client, stream).await {
                        error!(subsystem = "proxy_errors", "CONNECT tunnel error: {error}");
                    }
                }
                Err(e) => error!(subsystem = "proxy_errors", "CONNECT upgrade error: {}", e),
            }
        }
        .in_current_span(),
    );
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[derive(Debug, Error)]
pub enum UpstreamConnectError {
    #[error("An IO error occurred: {0}")]
    IO(#[from] std::io::Error),
    #[error("The upstream response contains an error")]
    UpstreamResponse(hyper::Response<Incoming>),
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
    backend: &KnownBackend,
    final_address: &str,
    state: Arc<RwLock<State>>,
    inbound_protocol: InboundHttpProtocol,
) -> Result<OutboundStream, UpstreamConnectError> {
    let socket = TcpStream::connect(backend.target_address).await?;

    let (stream, use_http2): (OutboundStream, bool) = if backend.identity_aware {
        debug!(
            subsystem = "proxy_access",
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
                warn!(
                    subsystem = "proxy_errors",
                    "Cannot HTTP CONNECT to upstream: {}", e
                );
            }
        });

        let mut response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(UpstreamConnectError::UpstreamResponse(response));
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
                warn!(
                    subsystem = "proxy_errors",
                    "Cannot HTTP CONNECT to upstream: {}", e
                );
            }
        });

        let mut response = sender
            .send_request(request)
            .await
            .map_err(io::Error::other)?;

        if !response.status().is_success() {
            return Err(UpstreamConnectError::UpstreamResponse(response));
        }

        let upgraded = hyper::upgrade::on(&mut response)
            .await
            .map_err(io::Error::other)?;

        Ok(Box::new(TokioIo::new(upgraded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uri(value: &str) -> http::Uri {
        value.parse().unwrap()
    }

    #[test]
    fn parses_authority_form_with_default_port() {
        let ConnectTarget { target, .. } = parse_connect_target(&uri("example.com")).unwrap();
        assert_eq!(target.host.as_str(), "example.com");
        assert_eq!(target.port, CONNECT_DEFAULT_PORT);
        assert!(!target.explicit_port);
    }

    #[test]
    fn parses_authority_form_with_explicit_port() {
        let ConnectTarget { target, .. } = parse_connect_target(&uri("example.com:8443")).unwrap();
        assert_eq!(target.host.as_str(), "example.com");
        assert_eq!(target.port, 8443);
        assert!(target.explicit_port);
    }

    #[test]
    fn rejects_absolute_form() {
        assert!(matches!(
            parse_connect_target(&uri("https://example.com:443/")),
            Err(ConnectTargetError::AbsoluteForm)
        ));
    }

    #[test]
    fn rejects_missing_authority() {
        assert!(matches!(
            parse_connect_target(&uri("/")),
            Err(ConnectTargetError::MissingAuthority)
        ));
    }
}
