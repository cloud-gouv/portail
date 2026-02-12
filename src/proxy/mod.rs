use std::{io::BufReader, sync::Arc};
use anyhow::bail;
use thiserror::Error;
use fast_socks5::SocksError;
use tokio::sync::RwLock;
use tracing::error;
use tokio_rustls::{TlsAcceptor, TlsStream, rustls::{RootCertStore, ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}, server::{VerifierBuilderError, WebPkiClientVerifier}}};
use webpki::anchor_from_trusted_cert;

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


#[derive(Debug, Error)]
enum MaterialError {
    #[error("Failed to parse PEM section")]
    SectionParsingError,
    #[error("Expected a certificate")]
    ExpectedCertificate,
    #[error("Expected a private key")]
    ExpectedPrivateKey
}

#[derive(Debug, Error)]
enum ServerTLSConfigError {
    #[error("Either the TLS chain or the private key is missing while the other is set")]
    MisconfiguredServerCertificates,
    #[error("Setting the single certificates failed: {0}")]
    ServerCertificateConfigError(#[from] tokio_rustls::rustls::Error),
    #[error("Failed during I/O: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Missing private key in the TLS private key file")]
    MissingPrivateKey,
    #[error("Failed to parse PEM files")]
    PEMParsingError,
    #[error("Unexpected material nature: {0}")]
    UnexpectedMaterialNature(#[from] MaterialError),
    #[error("Client verifier construction failed: {0}")]
    ClientVerifierBuilderError(#[from] VerifierBuilderError),
}


fn expect_certificate(item: rustls_pemfile::Item) -> Result<CertificateDer<'static>, MaterialError> {
    match item {
        rustls_pemfile::Item::X509Certificate(cert) => Ok(cert),
        _ => Err(MaterialError::ExpectedCertificate)
    }
}

fn expect_private_key(item: rustls_pemfile::Item) -> Result<PrivateKeyDer<'static>, MaterialError> {
    match item {
        rustls_pemfile::Item::Pkcs1Key(pkey) => Ok(pkey.into()),
        rustls_pemfile::Item::Sec1Key(pkey) => Ok(pkey.into()),
        rustls_pemfile::Item::Pkcs8Key(pkey) => Ok(pkey.into()),
        _ => Err(MaterialError::ExpectedPrivateKey)
    }
}

fn build_tls_acceptor(settings: &Settings) -> Result<Option<TlsAcceptor>, ServerTLSConfigError> {
    if let Some(ref listener) = settings.listener {
        let config = ServerConfig::builder();

        let config = if let Some(ref client_ca) = listener.cacert_file {
            let mut ca_file = BufReader::new(std::fs::File::open(&client_ca)?);
            let certs: Vec<_> = rustls_pemfile::read_all(&mut ca_file)
                .map(|item| 
                    item.map_err(|_| MaterialError::SectionParsingError).and_then(expect_certificate)
                )
                .collect::<Result<Vec<_>, _>>()?;

            let mut roots = RootCertStore::empty();
            for cert in certs {
                roots.add(cert)?;
            }

            config.with_client_cert_verifier(
                // TODO: support unauthenticated.
                WebPkiClientVerifier::builder(Arc::new(roots))
                .build()?
            )
        } else {
            config.with_no_client_auth()
        };

        let config = match (&listener.tls_chain, &listener.tls_privkey) {
            (Some(tls_chain), Some(tls_privkey)) => {
                let mut tls_chain_file = BufReader::new(std::fs::File::open(&tls_chain)?);
                let tls_chain_certs: Vec<_> = rustls_pemfile::read_all(&mut tls_chain_file)
                    .map(|item| item.map_err(|_| MaterialError::SectionParsingError).and_then(expect_certificate))
                    .collect::<Result<Vec<_>, _>>()?;
                let (tls_private_key, _) = rustls_pemfile::read_one_from_slice(&std::fs::read(&tls_privkey)?).map_err(|_| ServerTLSConfigError::PEMParsingError)?.ok_or(ServerTLSConfigError::MissingPrivateKey)?;
                config.with_single_cert(
                    tls_chain_certs,
                    expect_private_key(tls_private_key)?
                )?
            },

            (None, None) => {
                // No server TLS.
                return Ok(None);
            }

            _ => {
                return Err(ServerTLSConfigError::MisconfiguredServerCertificates);
            }
        };

        Ok(Some(TlsAcceptor::from(Arc::new(config))))
    } else {
        Ok(None)
    }
}

pub async fn start(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    listener: tokio::net::TcpListener
) -> anyhow::Result<()> {
    let tls_acceptor: Option<TlsAcceptor> = build_tls_acceptor(&settings)?;

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
