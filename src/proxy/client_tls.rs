use std::sync::Arc;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::RwLock,
};

use tokio_rustls::{TlsConnector, TlsStream, rustls::pki_types::ServerName};
use tracing::debug;

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
    let mut config = {
        let state_guard = state.read().await;
        (*state_guard.client_tls_config).clone()
    };

    config.alpn_protocols = alpn_protocols;

    let connector = TlsConnector::from(Arc::new(config));
    debug!("Performing a TLS connection to {domain:?}...");

    let tls_stream = connector.connect(domain, stream).await?;

    Ok(TlsStream::Client(tls_stream))
}
