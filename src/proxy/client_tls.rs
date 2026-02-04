use std::sync::Arc;

use tokio::{io::{AsyncRead, AsyncWrite}, sync::RwLock};

use tokio_rustls::{TlsConnector, TlsStream, rustls::{ClientConfig, pki_types::ServerName}};
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
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let config = {
        let state = state.read().await;

        match (state.root_store.clone(), state.client_cert_resolver.clone()) {
            (Some(root_store), Some(cert_resolver)) => ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_cert_resolver(cert_resolver),
            (Some(root_store), None) => ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
            (None, Some(_)) => {
                return Err(tokio::io::Error::new(tokio::io::ErrorKind::Other, "Client auth set without roots"));
            }
            // TODO: configure with default webpki
            (None, None) => panic!("webpki setup")
        }
    };

    let connector = TlsConnector::from(Arc::new(config));
    debug!("Performing a TLS connection to {domain:?}...");

    let tls_stream = connector.connect(domain, stream).await?;

    Ok(TlsStream::Client(tls_stream))
}
