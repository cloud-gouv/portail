use std::sync::Arc;
use anyhow::bail;
use thiserror::Error;
use fast_socks5::SocksError;
use tokio::sync::RwLock;
use tracing::error;
use tokio_rustls::{TlsAcceptor, TlsStream};

use crate::{config::Settings, proxy::context::RequestContext, state::State};

mod context;
mod client_tls;
mod protocol_detect;
mod socks5;
mod http_connect;

use context::InboundStream;
use socks5::serve_socks5;
use http_connect::serve_http_connect;
use protocol_detect::{DetectedProtocol, detect_protocol, detect_tls};

#[derive(Debug, Error)]
enum ProxyError {
    #[error("SOCKS5 error: {0}")]
    SocksError(#[from] SocksError),
    #[error("HTTP CONNECT error: {0}")]
    HTTPConnectError(String),
}

async fn serve_authenticated_proxy(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: RequestContext,
    stream: TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<()> {
    // TODO: extract context
    let (proto, stream) = detect_protocol(InboundStream::TlsStream(stream)).await?;

    if let InboundStream::TlsStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(settings, state, ctx, stream).await?,
            DetectedProtocol::Http => serve_http_connect(settings, state, stream).await?,
            DetectedProtocol::Unknown => bail!("Unknown protocol"),
        }
    }

    Ok(())
}

async fn serve_unauthenticated_proxy(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: RequestContext,
    stream: tokio::net::TcpStream
) -> anyhow::Result<()> {
    let (proto, stream) = detect_protocol(InboundStream::TcpStream(stream)).await?;
    if let InboundStream::TcpStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(settings, state, ctx, stream).await?,
            DetectedProtocol::Http => serve_http_connect(settings, state, stream).await?,
            DetectedProtocol::Unknown => bail!("Unknown protocol"),
        }
    }

    Ok(())
}

pub async fn start(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    listener: tokio::net::TcpListener
) -> anyhow::Result<()> {
    // TODO: construct a TLS acceptor based on the settings for the server side.
    let tls_acceptor: Option<TlsAcceptor> = None;

    loop {
        let (socket, addr) = listener.accept().await?;

        let acceptor = tls_acceptor.clone();
        let settings = settings.clone();
        let state = state.clone();
        let ctx = RequestContext::new(addr);

        tokio::spawn(async move {
            match detect_tls(&socket).await {
                Ok(true) => {
                    if let Some(acceptor) = acceptor {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                if let Err(e) =
                                    serve_authenticated_proxy(settings, state, ctx, TlsStream::Server(tls_stream)).await
                                {
                                    error!("TLS proxy error from {addr}: {e:?}");
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed from {addr}: {e:?}");
                            }
                        }
                    } else {
                        error!("TLS received from {addr}: but no TLS configuration set in the proxy");
                    }
                }

                Ok(false) => {
                    if let Err(e) = serve_unauthenticated_proxy(settings, state, ctx, socket).await
                    {
                        error!("Proxy error from {addr}: {e:?}");
                    }
                }

                Err(err) => {
                    error!("While detecting the header for TLS from {addr}, error occurred: {err:?}");
                }
            }
        });
    }
}
