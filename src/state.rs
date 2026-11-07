//! Contains the state of the application and various state transitions APIs.

use std::{
    collections::HashMap,
    io::BufReader,
    path::Path,
    sync::{Arc, atomic::AtomicUsize},
};

use rustls_pki_types::pem::PemObject;
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{VerifierBuilderError, WebPkiClientVerifier},
};
use tracing::{info, warn};

use crate::config::{BackendSettings, Settings};
use thiserror::Error;

pub struct ServerCertificates<'a> {
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub private_key: PrivateKeyDer<'a>,
}

pub struct State {
    pub backends: HashMap<String, BackendSettings>,
    pub default_backend: Option<String>,
    pub acl_rules: crate::acl::ACLRules,
    /// Trust anchors for inbound client certificates on the listener.
    pub listener_client_roots: Option<Arc<tokio_rustls::rustls::RootCertStore>>,
    /// Trust anchors for outbound backend TLS connections.
    pub backend_roots: Option<Arc<tokio_rustls::rustls::RootCertStore>>,
    pub server_certificates: Option<ServerCertificates<'static>>,
    pub listener_tls_config: Option<Arc<ServerConfig>>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
}

#[derive(Debug, Error)]
pub enum MaterialError {
    #[error("Failed to parse PEM section")]
    SectionParsingError,
}

#[derive(Debug, Error)]
pub enum ReloadTrustAnchorError {
    #[error("Unexpected material nature: {0}")]
    UnexpectedMaterialNature(#[from] MaterialError),
    #[error("Failed during I/O: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Adding a certificate to the root store failed: {0}")]
    RootStorePopulationError(#[from] tokio_rustls::rustls::Error),
}

#[derive(Debug, Error)]
pub enum ReloadServerCertificateError {
    #[error("Unexpected material nature: {0}")]
    UnexpectedMaterialNature(#[from] MaterialError),
    #[error("Either the TLS chain or the private key is missing while the other is set")]
    MisconfiguredServerCertificates,
    #[error("Failed to parse PEM files")]
    PEMParsingError,
    #[error("Failed during I/O: {0}")]
    IOError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum ReloadListenerTlsError {
    #[error("Setting the single certificates failed: {0}")]
    ServerCertificateConfigError(#[from] tokio_rustls::rustls::Error),
    #[error("Client verifier construction failed: {0}")]
    ClientVerifierBuilderError(#[from] VerifierBuilderError),
}

#[derive(Debug, Error)]
pub enum InitError {
    #[error("Failed to load server certificates: {0}")]
    LoadServerCertificatesError(#[from] ReloadServerCertificateError),
    #[error("Failed to load trust anchors: {0}")]
    LoadTrustAnchorError(#[from] ReloadTrustAnchorError),
    #[error("Failed to build listener TLS configuration: {0}")]
    LoadListenerTlsConfigError(#[from] ReloadListenerTlsError),
    #[error("Missing ACL filter file")]
    MissingACLFile,
    #[error("Failed to load ACL: {0}")]
    LoadACLError(#[from] crate::acl::LoadError),
}

fn load_roots(path: &Path) -> Result<Arc<RootCertStore>, ReloadTrustAnchorError> {
    let mut ca_file = BufReader::new(std::fs::File::open(path)?);
    let certs: Vec<_> = CertificateDer::pem_reader_iter(&mut ca_file)
        .map(|item| item.map_err(|_| MaterialError::SectionParsingError))
        .collect::<Result<Vec<_>, _>>()?;

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }

    Ok(Arc::new(roots))
}

impl State {
    pub fn reload_trust_anchors(
        &mut self,
        settings: &Settings,
    ) -> Result<(), ReloadTrustAnchorError> {
        let listener_roots = settings
            .listener
            .as_ref()
            .and_then(|listener| listener.cacert_file.as_deref())
            .map(load_roots)
            .transpose()?;

        let backend_roots = settings
            .escaper
            .as_ref()
            .and_then(|escaper| escaper.cacert_file.as_deref())
            .map(load_roots)
            .transpose()?;

        self.listener_client_roots = listener_roots;
        self.backend_roots = backend_roots;

        Ok(())
    }

    pub fn reload_server_certs(
        &mut self,
        settings: &Settings,
    ) -> Result<bool, ReloadServerCertificateError> {
        if let Some(ref listener) = settings.listener {
            match (&listener.tls_chain, &listener.tls_privkey) {
                (Some(tls_chain), Some(tls_privkey)) => {
                    let mut tls_chain_file = BufReader::new(std::fs::File::open(tls_chain)?);
                    let tls_chain_certs: Vec<_> =
                        CertificateDer::pem_reader_iter(&mut tls_chain_file)
                            .map(|item| item.map_err(|_| MaterialError::SectionParsingError))
                            .collect::<Result<Vec<_>, _>>()?;
                    let tls_private_key = PrivateKeyDer::from_pem_file(tls_privkey)
                        .map_err(|_| ReloadServerCertificateError::PEMParsingError)?;

                    self.server_certificates = Some(ServerCertificates {
                        cert_chain: tls_chain_certs,
                        private_key: tls_private_key,
                    });

                    return Ok(true);
                }

                (None, None) => {
                    // No server TLS.
                    return Ok(false);
                }

                _ => {
                    return Err(ReloadServerCertificateError::MisconfiguredServerCertificates);
                }
            }
        }

        Ok(false)
    }

    pub fn reload_listener_tls_config(&mut self) -> Result<(), ReloadListenerTlsError> {
        let Some(ref server_certificates) = self.server_certificates else {
            self.listener_tls_config = None;
            return Ok(());
        };

        let config = if let Some(ref roots) = self.listener_client_roots {
            ServerConfig::builder()
                .with_client_cert_verifier(WebPkiClientVerifier::builder(roots.clone()).build()?)
        } else {
            ServerConfig::builder().with_no_client_auth()
        };

        let mut config = config.with_single_cert(
            server_certificates.cert_chain.clone(),
            server_certificates.private_key.clone_key(),
        )?;
        config.alpn_protocols = vec![
            crate::proxy::protocols::ALPN_H2.to_vec(),
            crate::proxy::protocols::ALPN_HTTP1_1.to_vec(),
        ];

        self.listener_tls_config = Some(Arc::new(config));
        Ok(())
    }

    #[allow(dead_code)]
    pub fn reload_client_certs(&self) {}

    #[allow(dead_code)]
    pub fn reload_acl_rules(&mut self, settings: &Settings) {
        if let Some(ref acl_rules_path) = settings.filter_acl_rules_path {
            let new_acl = crate::acl::load_rules_from_file(acl_rules_path, settings);

            match new_acl {
                Ok(new_acl) => {
                    self.acl_rules = new_acl;
                    info!("ACL rules reloaded.");
                }
                Err(err) => {
                    warn!("Failed to reload ACL rules, keeping the old set of rules\n{err}");
                }
            }
        } else {
            warn!("ACL rule file disappeared from the settings file, keeping the old set of rules");
        }
    }
}

#[allow(dead_code)]
pub struct Statistics {
    pub nr_ongoing_client_connections: AtomicUsize,
    pub nr_tcp_connections: AtomicUsize,
    pub nr_udp_connections: AtomicUsize,
}

pub fn init(settings: &Settings) -> Result<State, InitError> {
    let mut state = State {
        backends: settings.backends.clone(),
        default_backend: settings.default_backend.clone(),
        acl_rules: crate::acl::load_rules_from_file(
            &settings
                .filter_acl_rules_path
                .clone()
                .ok_or(InitError::MissingACLFile)?,
            settings,
        )?,
        listener_client_roots: None,
        backend_roots: None,
        listener_tls_config: None,
        client_cert_resolver: None,
        server_certificates: None,
    };

    state.reload_trust_anchors(settings)?;

    // Load server certificates for the first time.
    if state.reload_server_certs(settings)? {
        info!("TLS listener is configured and available on this proxy.");
    } else {
        info!(
            "TLS is not configured and will not be available for requests. Use this only if your proxy is secured in another fashion: localhost binding or tunnel chaining."
        );
    }

    state.reload_listener_tls_config()?;

    Ok(state)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

    use super::*;

    #[test]
    fn builds_listener_tls_config() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let cert_path = root.join("nix/tests/certs/portail.corp/portail.corp.example.com.cert.pem");
        let key_path = root.join("nix/tests/certs/portail.corp/portail.corp.example.com.key.pem");

        let mut cert_reader = BufReader::new(std::fs::File::open(cert_path).unwrap());
        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_reader_iter(&mut cert_reader)
                .collect::<Result<_, _>>()
                .unwrap();
        let private_key = PrivateKeyDer::from_pem_file(key_path).unwrap();

        let mut state = State {
            backends: HashMap::new(),
            default_backend: None,
            acl_rules: crate::acl::ACLRules {
                hir: crate::acl::hir::ACLHir {
                    routes: Vec::new(),
                    policies: Vec::new(),
                },
            },
            listener_client_roots: None,
            backend_roots: None,
            server_certificates: Some(ServerCertificates {
                cert_chain,
                private_key,
            }),
            listener_tls_config: None,
            client_cert_resolver: None,
        };

        state.reload_listener_tls_config().unwrap();

        assert!(state.listener_tls_config.is_some());
    }
}
