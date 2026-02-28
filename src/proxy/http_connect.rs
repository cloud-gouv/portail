use crate::{
    config::{BackendSettings, Settings},
    proxy::{ProxyError, client_tls, context::RequestContext},
    state::State,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Incoming,
    header::{self, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, error, info, warn};

/// This is a workaround for the restriction `only auto traits can be used as additional traits in a trait object`
trait OutboundStreamIo: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> OutboundStreamIo for T {}

type OutboundStream = Box<dyn OutboundStreamIo + Send + Unpin>;

/// References:
/// - https://docs.rs/hyper/latest/hyper/upgrade/index.html
/// - https://github.com/hyperium/hyper/blob/master/examples/http_proxy.rs
/// - https://github.com/hyperium/hyper/blob/master/examples/upgrades.rs
pub async fn serve_http_connect<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: RequestContext,
    stream: S,
) -> Result<(), ProxyError> {
    let io = TokioIo::new(stream);

    // TODO: update ctx

    http1::Builder::new()
        .serve_connection(
            io,
            service_fn(move |req| {
                handle_http_request(req, ctx.clone(), settings.clone(), state.clone())
            }),
        )
        .with_upgrades()
        .await
        .map_err(|e| ProxyError::HTTPConnectError(e.to_string()))?;

    Ok(())
}

async fn handle_http_request(
    req: Request<Incoming>,
    mut ctx: RequestContext,
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    if req.method() != Method::CONNECT {
        debug!(
            "Unsupported HTTP method `{}` received, terminating connection",
            req.method()
        );
        // TODO: we might want to handle this case in the future
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        return Ok(resp);
    }

    // TODO: update ctx

    let Some(target_authority) = req.uri().authority() else {
        debug!("Invalid authority in CONNECT URI, terminating connection");
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::BAD_REQUEST;
        return Ok(resp);
    };

    let target_address = target_authority.to_string();
    let mut final_address = target_address.clone();
    let mut backend_ids: Vec<String> = Vec::with_capacity(1);
    if let Some(rule) = crate::acl::evaluate(
        target_authority.host(),
        &state.read().await.acl_rules,
        &mut ctx.acl_eval_ctx,
    ) {
        match rule.action {
            crate::acl::Action::Deny => {
                info!("Request to {} is blocked", target_authority.host());
                let mut resp = Response::new(empty_body());
                *resp.status_mut() = StatusCode::FORBIDDEN;
                return Ok(resp);
            }
            crate::acl::Action::Redirect(target) => {
                info!(
                    "Request to {} redirected to {}",
                    target_authority.host(),
                    target
                );
                final_address = target.to_string();
            }
            _ => {}
        }

        if let Some(recommended_backends) = rule.backends {
            backend_ids = recommended_backends;
        }
    }

    if backend_ids.is_empty() {
        if let Some(ref backend_id) = state.read().await.default_backend {
            backend_ids = vec![backend_id.clone()];
        }
    }

    backend_ids.reverse();

    let mut stream: Option<OutboundStream> = None;
    for backend_id in &backend_ids {
        let Some(backend) = settings.backends.get(backend_id) else {
            error!("Backend {} not found in settings", backend_id);
            continue;
        };
        debug!(
            "Backend {} selected for HTTP CONNECT to {}",
            backend.target_address, final_address
        );
        match connect_to_http_proxy_backend(backend, &final_address, state.clone()).await {
            Ok(upstream) => {
                stream = Some(upstream);
                break;
            }
            Err(err) => {
                debug!(
                    "Backend {} failed for HTTP CONNECT: {}, trying next",
                    backend.target_address, err
                );
            }
        }
    }
    if stream.is_none() {
        debug!(
            "No backend, establishing a direct connection to `{}`",
            final_address
        );
        match TcpStream::connect(&final_address).await {
            Ok(socket) => stream = Some(Box::new(socket)),
            Err(e) => debug!("Direct connection to `{}` failed: {}", final_address, e),
        }
    }

    let Some(mut stream) = stream else {
        let mut resp = Response::new(empty_body());
        *resp.status_mut() = StatusCode::BAD_GATEWAY;
        return Ok(resp);
    };

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut *stream).await {
                    debug!("CONNECT tunnel error: {}", e);
                }
            }
            Err(e) => debug!("CONNECT upgrade error: {}", e),
        }
    });

    let mut resp = Response::new(empty_body());
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut().insert(
        hyper::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );

    Ok(resp)
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Send CONNECT and return the stream on 2xx response
/// Ref: https://github.com/hyperium/hyper/blob/master/examples/client.rs
async fn connect_to_http_proxy_backend(
    backend: &BackendSettings,
    final_address: &str,
    state: Arc<RwLock<State>>,
) -> io::Result<OutboundStream> {
    let socket = TcpStream::connect(backend.target_address).await?;

    let stream: OutboundStream = if backend.identity_aware {
        debug!(
            "Backend is identity-aware, establishing a TLS connection to {}",
            backend.target_address
        );
        let backend_host = backend.target_address.ip().to_string();
        let domain = ServerName::try_from(backend_host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tls = client_tls::connect_using_tls_auth(socket, domain, state).await?;
        Box::new(tls)
    } else {
        Box::new(socket)
    };

    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
        .handshake(io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // We must await the connection (and enable upgrades)
    // https://docs.rs/hyper/latest/hyper/client/conn/http1/struct.Builder.html#method.handshake
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            warn!("Cannot HTTP CONNECT to upstream: {}", e);
        }
    });

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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut response = sender
        .send_request(request)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

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
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let stream: OutboundStream = Box::new(TokioIo::new(upgraded));

    Ok(stream)
}
