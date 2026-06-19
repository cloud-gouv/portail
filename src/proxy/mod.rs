use anyhow::bail;
use fast_socks5::SocksError;
use std::sync::Arc;
use thiserror::Error;
use tokio::{net::TcpStream, sync::RwLock};
use tokio_rustls::{
    TlsAcceptor, TlsStream,
    rustls::{
        ServerConfig,
        server::{VerifierBuilderError, WebPkiClientVerifier},
    },
};
use tracing::{Instrument, debug, error};

use crate::{config::Settings, proxy::context::OwnedRequestContext, state::State};

mod client_tls;
mod context;
mod http_connect;
mod protocol_detect;
mod socks5;

use context::InboundStream;
use http_connect::{serve_http1_connect, serve_http2_connect};
use protocol_detect::{ALPN_H2, ALPN_HTTP1_1, DetectedProtocol, detect_protocol, detect_tls};
use socks5::serve_socks5;

use lazy_static::lazy_static;
use prometheus::{
    HistogramVec, IntCounterVec, IntGaugeVec, register_histogram_vec, register_int_counter_vec,
    register_int_gauge_vec,
};

lazy_static! {
    static ref TOTAL_CONNECTIONS: IntCounterVec = register_int_counter_vec!(
        "portail_connections_total",
        "Number of total connections received",
        &["direction", "protocol"]
    )
    .unwrap();

    /// An active connection is a connection that have its final upstream connected but is not
    /// finished yet.
    static ref ACTIVE_CONNECTIONS: IntGaugeVec = register_int_gauge_vec!(
        "portail_active_connections",
        "Number of active connections",
        &["direction", "protocol"]
    )
    .unwrap();

    static ref ERRORED_CONNECTIONS: IntCounterVec = register_int_counter_vec!(
        "portail_connections_errors_total",
        "Number of total connections that had errors",
        &["error_type", "direction"]
    )
    .unwrap();

    static ref DIRECT_EXIT_TOTAL: IntCounterVec = register_int_counter_vec!(
        "portail_direct_exit_total",
        "Number of total direct exits performed",
        &["protocol"]
    ).unwrap();

    static ref UPSTREAMS_HEALTH: IntGaugeVec = register_int_gauge_vec!(
        "portail_upstream_up",
        "Whether an upstream is up or not",
        &["upstream"]
    )
    .unwrap();

    static ref UPSTREAMS_LATENCY: HistogramVec = register_histogram_vec!(
        "portail_upstream_latency_seconds",
        "Latency to connect to one of the upstream",
        &["upstream"]
    )
    .unwrap();

    static ref ACL_EVALUATION_TIMES: HistogramVec = register_histogram_vec!(
        "portail_acl_evaluation_seconds",
        "Duration in seconds of ACL evaluations",
        &["decision"]
    )
    .unwrap();
}

#[derive(Debug, Error)]
enum ProxyError {
    #[error("SOCKS5 error: {0}")]
    SocksError(#[from] SocksError),
    #[error("HTTP CONNECT error: {0}")]
    HTTPConnectError(String),
}

macro_rules! count_errors {
    ($expr:expr, $label:expr) => {
        match $expr.await {
            Ok(v) => Ok(v),
            Err(e) => {
                ERRORED_CONNECTIONS
                    .with_label_values(&[$label, "ingress"])
                    .inc();
                Err(e)
            }
        }
    };
}

async fn serve_authenticated_proxy(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: OwnedRequestContext,
    stream: TlsStream<tokio::net::TcpStream>,
) -> anyhow::Result<()> {
    // TODO: extract context

    let (proto, stream) = detect_protocol(InboundStream::TlsStream(stream)).await?;

    if let InboundStream::TlsStream(stream) = stream {
        TOTAL_CONNECTIONS
            .with_label_values(&["ingress", proto.as_label()])
            .inc();
        let _guard = ActiveConnectionGuard::new("ingress", proto);

        match proto {
            DetectedProtocol::Socks5 => {
                count_errors!(serve_socks5(settings, state, ctx, stream), "socks5_error")?
            }
            DetectedProtocol::Http1 => count_errors!(
                serve_http1_connect(settings, state, ctx, stream),
                "http1_error"
            )?,
            DetectedProtocol::Http2 => count_errors!(
                serve_http2_connect(settings, state, ctx, stream),
                "http2_error"
            )?,
            DetectedProtocol::Unknown => {
                ERRORED_CONNECTIONS
                    .with_label_values(&["unsupported_proxy_protocol", "ingress"])
                    .inc();
                bail!("Unknown protocol")
            }
        }

        ACTIVE_CONNECTIONS
            .with_label_values(&["ingress", proto.as_label()])
            .dec();
    }

    Ok(())
}

struct ActiveConnectionGuard {
    protocol: DetectedProtocol,
    direction: &'static str,
}

impl ActiveConnectionGuard {
    pub fn new(direction: &'static str, protocol: DetectedProtocol) -> Self {
        ACTIVE_CONNECTIONS
            .with_label_values(&[direction, protocol.as_label()])
            .inc();
        Self {
            direction,
            protocol,
        }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS
            .with_label_values(&[self.direction, self.protocol.as_label()])
            .dec();
    }
}

async fn serve_unauthenticated_proxy(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: OwnedRequestContext,
    stream: tokio::net::TcpStream,
) -> anyhow::Result<()> {
    let (proto, stream) = detect_protocol(InboundStream::TcpStream(stream)).await?;

    TOTAL_CONNECTIONS
        .with_label_values(&["ingress", proto.as_label()])
        .inc();

    let _guard = ActiveConnectionGuard::new("ingress", proto);

    if let InboundStream::TcpStream(stream) = stream {
        match proto {
            DetectedProtocol::Socks5 => {
                count_errors!(serve_socks5(settings, state, ctx, stream), "socks5_error")?
            }
            DetectedProtocol::Http1 => count_errors!(
                serve_http1_connect(settings, state, ctx, stream),
                "http1_error"
            )?,
            DetectedProtocol::Http2 => count_errors!(
                serve_http2_connect(settings, state, ctx, stream),
                "http2_error"
            )?,
            DetectedProtocol::Unknown => {
                ERRORED_CONNECTIONS
                    .with_label_values(&["unsupported_proxy_protocol", "ingress"])
                    .inc();

                bail!("Unknown protocol")
            }
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
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    socket: TcpStream,
    tls_acceptor: Option<TlsAcceptor>,
    ctx: OwnedRequestContext,
) {
    debug!(subsystem = "proxy_access", "Accepting a proxy connection");

    let acceptor = tls_acceptor.clone();
    let settings = settings.clone();
    let state = state.clone();

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
                                    settings,
                                    state,
                                    ctx,
                                    TlsStream::Server(tls_stream),
                                )
                                .await
                                {
                                    error!(subsystem = "proxy_errors", "TLS proxy error: {e:?}");
                                }
                            }
                            Err(e) => {
                                ERRORED_CONNECTIONS
                                    .with_label_values(&["tls_handshake_failure", "ingress"])
                                    .inc();
                                error!(subsystem = "proxy_errors", "TLS handshake failed: {e:?}");
                            }
                        }
                    } else {
                        ERRORED_CONNECTIONS
                            .with_label_values(&["unsupported_tls", "ingress"])
                            .inc();

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
                    if let Err(e) = serve_unauthenticated_proxy(settings, state, ctx, socket).await
                    {
                        error!(subsystem = "proxy_errors", "Proxy error: {e:?}");
                    }
                }

                Err(err) => {
                    ERRORED_CONNECTIONS
                        .with_label_values(&["malformed_tls", "ingress"])
                        .inc();

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

pub async fn start(
    settings: Arc<Settings>,
    state: Arc<RwLock<State>>,
    listener: tokio::net::TcpListener,
) -> anyhow::Result<()> {
    let tls_acceptor: Option<TlsAcceptor> = build_tls_acceptor(&settings, state.clone()).await?;

    loop {
        let (socket, addr) = listener.accept().await?;
        let ctx = OwnedRequestContext::new(addr);
        accept_client(
            settings.clone(),
            state.clone(),
            socket,
            tls_acceptor.clone(),
            ctx,
        )
        .await;
    }
}
