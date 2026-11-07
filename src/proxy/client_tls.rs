use std::sync::Arc;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
};

use tokio_rustls::{
    TlsConnector, TlsStream,
    rustls::{ClientConfig, RootCertStore, client::ResolvesClientCert, pki_types::ServerName},
};
use tracing::debug;

/// TLS material for outbound backend connections.
pub struct BackendTlsConfig {
    roots: Arc<RootCertStore>,
    client_cert_resolver: Option<Arc<dyn ResolvesClientCert>>,
}

impl BackendTlsConfig {
    fn from_state(state: &crate::state::State) -> Result<Self, tokio::io::Error> {
        let Some(roots) = state.backend_roots.clone() else {
            return Err(tokio::io::Error::other(
                "No backend TLS trust anchors configured for identity-aware backend",
            ));
        };

        Ok(Self {
            roots,
            client_cert_resolver: state.client_cert_resolver.clone(),
        })
    }

    fn client_config(&self, alpn_protocols: Vec<Vec<u8>>) -> ClientConfig {
        let mut config = match self.client_cert_resolver.clone() {
            Some(cert_resolver) => ClientConfig::builder()
                .with_root_certificates(self.roots.clone())
                .with_client_cert_resolver(cert_resolver),
            None => ClientConfig::builder()
                .with_root_certificates(self.roots.clone())
                .with_no_client_auth(),
        };

        config.alpn_protocols = alpn_protocols;
        config
    }
}

/// This connects to a target server using a mTLS mechanism.
/// The roots and client certs are fetched from the state where
/// they are the freshest and cached upon the first connection.
///
/// The state may be reloaded with new material.
///
/// NOTE: Revocation via CRLs are not handled.
pub async fn connect_using_tls_auth<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: IO,
    domain: ServerName<'static>,
    state: Arc<RwLock<crate::state::State>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let config = {
        let state = state.read().await;
        BackendTlsConfig::from_state(&state)?.client_config(alpn_protocols)
    };

    let connector = TlsConnector::from(Arc::new(config));
    debug!("Performing a TLS connection to {domain:?}...");

    let tls_stream = connector.connect(domain, stream).await?;

    Ok(TlsStream::Client(tls_stream))
}
