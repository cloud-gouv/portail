//! Contains the state of the application and various state transitions APIs.

use std::{
    io::BufReader,
    sync::{Arc, atomic::AtomicUsize},
};

use rustls_pki_types::pem::PemObject;
use tokio_rustls::rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use tracing::{info, warn};

use crate::config::Settings;
use thiserror::Error;

pub struct ServerCertificates<'a> {
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub private_key: PrivateKeyDer<'a>,
}

pub struct State {
    pub default_backend: Option<String>,
    pub acl_rules: crate::acl::ACLRules,
    pub root_store: Option<Arc<tokio_rustls::rustls::RootCertStore>>,
    pub server_certificates: Option<ServerCertificates<'static>>,
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
pub enum InitError {
    #[error("Failed to load server certificates: {0}")]
    LoadServerCertificatesError(#[from] ReloadServerCertificateError),
    #[error("Failed to load trust anchors: {0}")]
    LoadTrustAnchorError(#[from] ReloadTrustAnchorError),
    #[error("Missing ACL filter file")]
    MissingACLFile,
    #[error("Failed to load ACL: {0}")]
    LoadACLError(#[from] crate::acl::LoadError),
}

impl State {
    pub fn reload_trust_anchors(
        &mut self,
        settings: &Settings,
    ) -> Result<(), ReloadTrustAnchorError> {
        if let Some(ref listener) = settings.listener
            && let Some(ref client_ca) = listener.cacert_file
        {
            let mut ca_file = BufReader::new(std::fs::File::open(client_ca)?);
            let certs: Vec<_> = CertificateDer::pem_reader_iter(&mut ca_file)
                .map(|item| item.map_err(|_| MaterialError::SectionParsingError))
                .collect::<Result<Vec<_>, _>>()?;

            let mut roots = RootCertStore::empty();
            for cert in certs {
                roots.add(cert)?;
            }

            self.root_store = Some(Arc::new(roots));
        }

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
        default_backend: settings.default_backend.clone(),
        acl_rules: crate::acl::load_rules_from_file(
            &settings
                .filter_acl_rules_path
                .clone()
                .ok_or(InitError::MissingACLFile)?,
            settings,
        )?,
        root_store: None,
        client_cert_resolver: None,
        server_certificates: None,
    };

    // Load server certificates and trust anchors for the first time.
    if state.reload_server_certs(settings)? {
        info!("TLS listener is configured and available on this proxy.");
    } else {
        info!(
            "TLS is not configured and will not be available for requests. Use this only if your proxy is secured in another fashion: localhost binding or tunnel chaining."
        );
    }

    state.reload_trust_anchors(settings)?;

    Ok(state)
}
