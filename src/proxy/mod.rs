use anyhow::bail;
use fast_socks5::SocksError;
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    net::TcpStream,
    sync::{RwLock, Semaphore, broadcast},
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor, TlsStream,
    rustls::{
        ServerConfig,
        server::{VerifierBuilderError, WebPkiClientVerifier},
    },
};
use tracing::{Instrument, debug, error, warn};

use crate::{
    acl::ast::OwnedConcreteOperand,
    config::Settings,
    dns::DnsResolver,
    events::event_type,
    proxy::{
        context::OwnedRequestContext,
        identity::PeerIdentity,
        protocols::{DetectedProtocol, HttpVersion},
    },
    rpc::fr_gouv_portail_control::Event,
    state::State,
};

mod client_tls;
pub mod context;
pub mod host;
mod http_connect;
pub mod identity;
mod protocols;
mod socks5;
pub mod target;

use context::InboundStream;
use http_connect::{serve_http1_connect, serve_http2_connect};
use socks5::serve_socks5;

pub struct ProxyRuntime {
    pub settings: Arc<Settings>,
    pub state: Arc<RwLock<State>>,
    pub dns: Arc<DnsResolver>,
    pub event_bus: broadcast::Sender<Event>,
}

impl ProxyRuntime {
    pub fn new(settings: Arc<Settings>, state: Arc<RwLock<State>>) -> anyhow::Result<Arc<Self>> {
        let dns = DnsResolver::from_settings(&settings.dns)?;
        let (event_bus, _) = broadcast::channel(2048);

        Ok(Arc::new(Self {
            settings,
            state,
            dns,
            event_bus,
        }))
    }

    /// Push an event to all subscribers on the event bus.
    /// No-op if the buffer is full or there's no subscriber.
    pub fn emit(&self, event: Event) {
        let _ = self.event_bus.send(event);
    }
}

#[derive(Debug, Error)]
enum ProxyError {
    #[error("SOCKS5 error: {0}")]
    SocksError(#[from] SocksError),
    #[error("HTTP CONNECT error: {0}")]
    HTTPConnectError(String),
}

async fn serve_authenticated_proxy(
    rt: Arc<ProxyRuntime>,
    ctx: OwnedRequestContext,
    stream: TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<()> {
    // TODO: extract context

    let (proto, stream) = protocols::detect_protocol(InboundStream::TlsStream(stream)).await?;

    if let InboundStream::TlsStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(rt, ctx, stream).await?,
            DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1) => {
                serve_http1_connect(rt, ctx, stream).await?
            }
            DetectedProtocol::PlaintextHttp(HttpVersion::Http2_0) => {
                serve_http2_connect(rt, ctx, stream).await?
            }
            DetectedProtocol::Tls(info) => {
                let alpn = info.alpn.unwrap_or(vec![HttpVersion::Http1_1]);

                if alpn.contains(&HttpVersion::Http2_0) {
                    serve_http2_connect(rt, ctx, stream).await?
                } else if alpn.contains(&HttpVersion::Http1_1) {
                    serve_http1_connect(rt, ctx, stream).await?
                } else {
                    bail!("Unsupported ALPN negotiation: {alpn:?}");
                }
            }
            DetectedProtocol::Ssh | DetectedProtocol::PlaintextHttp(_) => {
                bail!("Unsupported protocol: {proto:?}")
            }
            DetectedProtocol::Unknown => bail!("Unknown protocol"),
        }
    }

    Ok(())
}

async fn serve_unauthenticated_proxy(
    rt: Arc<ProxyRuntime>,
    ctx: OwnedRequestContext,
    stream: tokio::net::TcpStream,
) -> anyhow::Result<()> {
    let (proto, stream) = protocols::detect_protocol(InboundStream::TcpStream(stream)).await?;
    if let InboundStream::TcpStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(rt, ctx, stream).await?,
            DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1) => {
                serve_http1_connect(rt, ctx, stream).await?
            }
            DetectedProtocol::PlaintextHttp(HttpVersion::Http2_0) => {
                serve_http2_connect(rt, ctx, stream).await?
            }
            DetectedProtocol::Tls(info) => {
                let alpn = info.alpn.unwrap_or(vec![HttpVersion::Http1_1]);

                if alpn.contains(&HttpVersion::Http2_0) {
                    serve_http2_connect(rt, ctx, stream).await?
                } else if alpn.contains(&HttpVersion::Http1_1) {
                    serve_http1_connect(rt, ctx, stream).await?
                } else {
                    bail!("Unsupported ALPN negotiation: {alpn:?}");
                }
            }
            DetectedProtocol::Ssh | DetectedProtocol::PlaintextHttp(_) => {
                bail!("Unsupported protocol: {proto:?}")
            }
            DetectedProtocol::Unknown => bail!("Unknown protocol"),
        }
    }

    Ok(())
}

#[derive(Debug, Error)]
enum ServerTLSConfigError {
    #[error("Setting the single certificates failed: {0}")]
    ServerCertificateConfigError(#[from] tokio_rustls::rustls::Error),
    #[error("Client verifier construction failed: {0}")]
    ClientVerifierBuilderError(#[from] VerifierBuilderError),
}

async fn build_tls_acceptor(
    settings: &Settings,
    state: Arc<RwLock<State>>,
) -> Result<Option<TlsAcceptor>, ServerTLSConfigError> {
    if settings.listener.is_some() {
        let state = state.read().await;
        let config = ServerConfig::builder();

        let config = if let Some(ref roots) = state.listener_client_roots {
            config.with_client_cert_verifier(
                // TODO: support unauthenticated.
                WebPkiClientVerifier::builder(roots.clone()).build()?,
            )
        } else {
            config.with_no_client_auth()
        };

        if let Some(ref server_certs) = state.server_certificates {
            let mut config = config.with_single_cert(
                server_certs.cert_chain.clone(),
                server_certs.private_key.clone_key(),
            )?;
            config.alpn_protocols = vec![
                protocols::ALPN_H2.to_vec(),
                protocols::ALPN_HTTP1_1.to_vec(),
            ];
            Ok(Some(TlsAcceptor::from(Arc::new(config))))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

fn insert_peer_identity(
    stream: &tokio_rustls::server::TlsStream<TcpStream>,
    ctx: &mut OwnedRequestContext,
) {
    let Some(certificates) = stream.get_ref().1.peer_certificates() else {
        return;
    };
    let Some(leaf) = certificates.first() else {
        return;
    };

    let identity = match PeerIdentity::from_der(leaf.as_ref()) {
        Ok(identity) => identity,
        Err(error) => {
            warn!(
                subsystem = "proxy_errors",
                "Cannot parse peer certificate identity: {error}"
            );
            return;
        }
    };

    if let Some(subject_cn) = identity.subject_cn {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.subject_cn".into(),
            OwnedConcreteOperand::String(subject_cn),
        );
    }

    if let Some(issuer_cn) = identity.issuer_cn {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.issuer_cn".into(),
            OwnedConcreteOperand::String(issuer_cn),
        );
    }

    ctx.acl_ctx.insert(
        "tunnel.client.cert.serial".into(),
        OwnedConcreteOperand::String(identity.serial),
    );
    ctx.acl_ctx.insert(
        "tunnel.client.cert.not_before".into(),
        OwnedConcreteOperand::Number(identity.not_before),
    );
    ctx.acl_ctx.insert(
        "tunnel.client.cert.not_after".into(),
        OwnedConcreteOperand::Number(identity.not_after),
    );

    if !identity.san_dns.is_empty() {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.san_dns".into(),
            OwnedConcreteOperand::Set(identity.san_dns),
        );
    }

    if !identity.san_uri.is_empty() {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.san_uri".into(),
            OwnedConcreteOperand::Set(identity.san_uri),
        );
    }

    if !identity.san_email.is_empty() {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.san_email".into(),
            OwnedConcreteOperand::Set(identity.san_email),
        );
    }

    if !identity.san_ip.is_empty() {
        ctx.acl_ctx.insert(
            "tunnel.client.cert.san_ip".into(),
            OwnedConcreteOperand::Set(identity.san_ip),
        );
    }
}

#[tracing::instrument(skip_all, fields(trace_id = %ctx.trace_id, client_address = %ctx.client_address, subsystem = "proxy_access"))]
pub async fn accept_client(
    rt: Arc<ProxyRuntime>,
    socket: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    mut ctx: OwnedRequestContext,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    debug!(subsystem = "proxy_access", "Accepting a proxy connection");

    let acceptor = tls_acceptor.clone();
    let rt = rt.clone();

    tokio::spawn(
        async move {
            // The permit is dropped when the spawned task completes.
            let _permit = permit;
            // Wrap TLS detection in a timeout to prevent slowloris attacks
            // where a client connects and sends nothing.
            match timeout(
                rt.settings.handshake_timeout,
                protocols::tls::has_tls_prefix(&socket),
            )
            .await
            {
                Ok(Ok(true)) => {
                    debug!(subsystem = "proxy_access", "TLS detected");
                    if let Some(acceptor) = acceptor {
                        match timeout(rt.settings.handshake_timeout, acceptor.accept(socket)).await
                        {
                            Ok(Ok(tls_stream)) => {
                                debug!(
                                    subsystem = "proxy_access",
                                    "Authenticated TLS stream (client certificates)"
                                );

                                ctx.client_transport = crate::proxy::context::ClientTransport::Tls;
                                ctx.acl_ctx.insert(
                                    "tunnel.transport".into(),
                                    OwnedConcreteOperand::String(
                                        ctx.client_transport.as_str().into(),
                                    ),
                                );
                                ctx.acl_ctx.insert(
                                    "client.auth".into(),
                                    OwnedConcreteOperand::String("tls".into()),
                                );
                                ctx.acl_ctx.insert(
                                    "tunnel.client.auth".into(),
                                    OwnedConcreteOperand::String("mtls".into()),
                                );
                                insert_peer_identity(&tls_stream, &mut ctx);

                                if let Err(e) = serve_authenticated_proxy(
                                    rt,
                                    ctx,
                                    TlsStream::Server(tls_stream),
                                )
                                .await
                                {
                                    error!(subsystem = "proxy_errors", "TLS proxy error: {e:?}");
                                }
                            }
                            Ok(Err(e)) => {
                                error!(subsystem = "proxy_errors", "TLS handshake failed: {e:?}");
                                rt.emit(Event::new(
                                    event_type::GENERAL_ERROR,
                                    tr::tr!("TLS handshake failed: {error}", error = e.to_string()),
                                ));
                            }
                            Err(_elapsed) => {
                                warn!(
                                    subsystem = "proxy_access",
                                    "TLS handshake timed out, closing connection",
                                );
                            }
                        }
                    } else {
                        error!(
                            subsystem = "proxy_errors",
                            "TLS received but no TLS configuration set in the proxy"
                        );
                    }
                }

                Ok(Ok(false)) => {
                    debug!(
                        subsystem = "proxy_access",
                        "No TLS detected, serving unauthenticated and plaintext requests",
                    );

                    ctx.client_transport = crate::proxy::context::ClientTransport::Plaintext;
                    ctx.acl_ctx.insert(
                        "tunnel.transport".into(),
                        OwnedConcreteOperand::String(ctx.client_transport.as_str().into()),
                    );
                    ctx.acl_ctx.insert(
                        "tunnel.client.auth".into(),
                        OwnedConcreteOperand::String("none".into()),
                    );
                    ctx.acl_ctx.insert(
                        "client.auth".into(),
                        OwnedConcreteOperand::String("none".into()),
                    );

                    if let Err(e) = serve_unauthenticated_proxy(rt, ctx, socket).await {
                        error!(subsystem = "proxy_errors", "Proxy error: {e:?}");
                    }
                }

                Ok(Err(err)) => {
                    error!(
                        subsystem = "proxy_errors",
                        "While detecting the header for TLS, error occurred: {err:?}"
                    );
                }

                Err(_elapsed) => {
                    warn!(
                        subsystem = "proxy_access",
                        "TLS detection timed out, closing connection",
                    );
                }
            }
        }
        .in_current_span(),
    );
}

pub async fn start(
    rt: Arc<ProxyRuntime>,
    listener: tokio::net::TcpListener,
    max_connections: usize,
) -> anyhow::Result<()> {
    use nix::errno::Errno;
    use std::io::ErrorKind;
    let tls_acceptor: Option<TlsAcceptor> =
        build_tls_acceptor(&rt.settings, rt.state.clone()).await?;

    let conn_semaphore = Arc::new(Semaphore::new(max_connections.min(Semaphore::MAX_PERMITS)));

    loop {
        let (socket, addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                if e.raw_os_error() as Option<i32> == Some(Errno::EMFILE as i32)
                    || e.raw_os_error() as Option<i32> == Some(Errno::ENFILE as i32)
                    || e.kind() == ErrorKind::ConnectionAborted
                    || e.kind() == ErrorKind::Interrupted
                {
                    error!(
                        subsystem = "proxy_errors",
                        "Transient accept error, backing off: {e}"
                    );

                    // Give 100ms until you terminate the client connection.
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    // This is non fatal.
                    continue;
                }
                return Err(e.into());
            }
        };

        let permit = match conn_semaphore.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                error!(
                    subsystem = "proxy_errors",
                    client_address = %addr,
                    "Connection rejected: proxy at capacity ({max} concurrent connections)",
                    max = max_connections
                );

                continue;
            }
        };

        let ctx = OwnedRequestContext::new(addr);
        accept_client(rt.clone(), socket, tls_acceptor.clone(), ctx, permit).await;
    }
}
