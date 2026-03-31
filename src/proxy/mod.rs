use anyhow::bail;
use fast_socks5::SocksError;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio_rustls::{
    TlsAcceptor, TlsStream,
    rustls::{
        ServerConfig,
        server::{VerifierBuilderError, WebPkiClientVerifier},
    },
};
use tracing::error;

use crate::{config::Settings, proxy::context::InitialRequestContext, state::State};

mod client_tls;
mod context;
mod http_connect;
mod protocol_detect;
mod socks5;

use context::InboundStream;
use http_connect::{serve_http1_connect, serve_http2_connect};
use protocol_detect::{ALPN_H2, ALPN_HTTP1_1, DetectedProtocol, detect_protocol, detect_tls};
use socks5::serve_socks5;

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
    ctx: InitialRequestContext,
    stream: TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<()> {
    // TODO: extract context

    let (proto, stream) = detect_protocol(InboundStream::TlsStream(stream)).await?;

    if let InboundStream::TlsStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(settings, state, ctx, stream).await?,
            DetectedProtocol::Http1 => serve_http1_connect(settings, state, ctx, stream).await?,
            DetectedProtocol::Http2 => serve_http2_connect(settings, state, ctx, stream).await?,
            DetectedProtocol::Unknown => bail!("Unknown protocol"),
        }
    }

    Ok(())
}

async fn serve_unauthenticated_proxy(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: InitialRequestContext,
    stream: tokio::net::TcpStream,
) -> anyhow::Result<()> {
    let (proto, stream) = detect_protocol(InboundStream::TcpStream(stream)).await?;
    if let InboundStream::TcpStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => serve_socks5(settings, state, ctx, stream).await?,
            DetectedProtocol::Http1 => serve_http1_connect(settings, state, ctx, stream).await?,
            DetectedProtocol::Http2 => serve_http2_connect(settings, state, ctx, stream).await?,
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

pub async fn start(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let tls_acceptor: Option<TlsAcceptor> = build_tls_acceptor(&settings, state.clone()).await?;

    loop {
        let (socket, addr) = listener.accept().await?;

        let acceptor = tls_acceptor.clone();
        let settings = settings.clone();
        let state = state.clone();
        let ctx = InitialRequestContext::new(addr);

        tokio::spawn(async move {
            match detect_tls(&socket).await {
                Ok(true) => {
                    if let Some(acceptor) = acceptor {
                        match acceptor.accept(socket).await {
                            Ok(tls_stream) => {
                                if let Err(e) = serve_authenticated_proxy(
                                    settings,
                                    state,
                                    ctx,
                                    TlsStream::Server(tls_stream),
                                )
                                .await
                                {
                                    error!("TLS proxy error from {addr}: {e:?}");
                                }
                            }
                            Err(e) => {
                                error!("TLS handshake failed from {addr}: {e:?}");
                            }
                        }
                    } else {
                        error!(
                            "TLS received from {addr}: but no TLS configuration set in the proxy"
                        );
                    }
                }

                Ok(false) => {
                    if let Err(e) = serve_unauthenticated_proxy(settings, state, ctx, socket).await
                    {
                        error!("Proxy error from {addr}: {e:?}");
                    }
                }

                Err(err) => {
                    error!(
                        "While detecting the header for TLS from {addr}, error occurred: {err:?}"
                    );
                }
            }
        });
    }
}
