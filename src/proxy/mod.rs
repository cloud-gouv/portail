use anyhow::bail;
use fast_socks5::SocksError;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock, time::timeout};
use tokio_rustls::{
    TlsAcceptor, TlsStream,
    rustls::{
        ServerConfig,
        server::{VerifierBuilderError, WebPkiClientVerifier},
    },
};
use tracing::{Instrument, debug, error};

use crate::{
    config::Settings, dns::DnsResolver, proxy::context::OwnedRequestContext, state::State,
};

mod client_tls;
mod context;
mod http_connect;
mod protocol_detect;
mod socks5;

use context::InboundStream;
use http_connect::{serve_http1_connect, serve_http2_connect};
use protocol_detect::{ALPN_H2, ALPN_HTTP1_1, DetectedProtocol, detect_protocol, detect_tls};
use socks5::serve_socks5;

pub struct ProxyRuntime {
    pub settings: Arc<Settings>,
    pub state: Arc<RwLock<State>>,
    pub dns: Arc<DnsResolver>,
}

impl ProxyRuntime {
    pub fn new(settings: Arc<Settings>, state: Arc<RwLock<State>>) -> anyhow::Result<Arc<Self>> {
        let dns = DnsResolver::from_settings(&settings.dns)?;

        Ok(Arc::new(Self {
            settings,
            state,
            dns,
        }))
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

    let (proto, stream) = detect_protocol(InboundStream::TlsStream(stream)).await?;

    if let InboundStream::TlsStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(rt, ctx, stream).await?,
            DetectedProtocol::Http1 => serve_http1_connect(rt, ctx, stream).await?,
            DetectedProtocol::Http2 => serve_http2_connect(rt, ctx, stream).await?,
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
    let (proto, stream) = detect_protocol(InboundStream::TcpStream(stream)).await?;
    if let InboundStream::TcpStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(rt, ctx, stream).await?,
            DetectedProtocol::Http1 => serve_http1_connect(rt, ctx, stream).await?,
            DetectedProtocol::Http2 => serve_http2_connect(rt, ctx, stream).await?,
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

        let config = if let Some(ref roots) = state.root_store {
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
            config.alpn_protocols = vec![ALPN_H2.to_vec(), ALPN_HTTP1_1.to_vec()];
            Ok(Some(TlsAcceptor::from(Arc::new(config))))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

#[tracing::instrument(skip_all, fields(trace_id = %ctx.trace_id, client_address = %ctx.client_address, subsystem = "proxy_access"))]
pub async fn accept_client(
    rt: Arc<ProxyRuntime>,
    socket: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    ctx: OwnedRequestContext,
) {
    debug!(subsystem = "proxy_access", "Accepting a proxy connection");

    let acceptor = tls_acceptor.clone();
    let rt = rt.clone();

    tokio::spawn(
        async move {
            match detect_tls(&socket).await {
                Ok(true) => {
                    debug!(subsystem = "proxy_access", "TLS detected");
                    if let Some(acceptor) = acceptor {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                debug!(
                                    subsystem = "proxy_access",
                                    "Authenticated TLS stream (client certificates)"
                                );
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
                            Err(e) => {
                                error!(subsystem = "proxy_errors", "TLS handshake failed: {e:?}");
                            }
                        }
                    } else {
                        error!(
                            subsystem = "proxy_errors",
                            "TLS received but no TLS configuration set in the proxy"
                        );
                    }
                }

                Ok(false) => {
                    debug!(
                        subsystem = "proxy_access",
                        "No TLS detected, serving unauthenticated requests",
                    );
                    if let Err(e) = serve_unauthenticated_proxy(rt, ctx, socket).await {
                        error!(subsystem = "proxy_errors", "Proxy error: {e:?}");
                    }
                }

                Err(err) => {
                    error!(
                        subsystem = "proxy_errors",
                        "While detecting the header for TLS, error occurred: {err:?}"
                    );
                }
            }
        }
        .in_current_span(),
    );
}

pub async fn start(rt: Arc<ProxyRuntime>, listener: tokio::net::TcpListener) -> anyhow::Result<()> {
    let tls_acceptor: Option<TlsAcceptor> =
        build_tls_acceptor(&rt.settings, rt.state.clone()).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        let ctx = OwnedRequestContext::new(addr);
        accept_client(rt.clone(), socket, tls_acceptor.clone(), ctx).await;
    }
}

/// Tries each address in order.
pub(crate) async fn connect_tcp(
    ips: &[IpAddr],
    port: u16,
    connect_timeout: Duration,
) -> io::Result<(TcpStream, SocketAddr)> {
    let per_addr_timeout = connect_timeout
        .checked_div(ips.len().max(1) as u32)
        .unwrap_or(connect_timeout);
    let mut last_err = None;

    for &ip in ips {
        let addr = SocketAddr::new(ip, port);
        match timeout(per_addr_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok((stream, addr)),
            Ok(Err(err)) => last_err = Some(err),
            Err(err) => {
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, err));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotConnected, "no addresses to connect to")
    }))
}
