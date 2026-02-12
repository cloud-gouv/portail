use std::{io::BufReader, sync::{Arc, atomic::AtomicUsize}};

use tokio_rustls::rustls::{RootCertStore, pki_types::{CertificateDer, PrivateKeyDer}};

use crate::config::Settings;
use thiserror::Error;

///! Contains the state of the application and various state transitions APIs.

pub struct ServerCertificates<'a> {
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub private_key: PrivateKeyDer<'a>,
}

pub struct State {
    pub default_backend: Option<String>,
    pub acl_rules: Vec<crate::acl::ACLRule>,
    pub root_store: Option<Arc<tokio_rustls::rustls::RootCertStore>>,
    pub server_certificates: Option<ServerCertificates<'static>>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
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
enum ReloadTrustAnchorError {
    #[error("Unexpected material nature: {0}")]
    UnexpectedMaterialNature(#[from] MaterialError),
    #[error("Failed during I/O: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Adding a certificate to the root store failed: {0}")]
    RootStorePopulationError(#[from] tokio_rustls::rustls::Error),
}

#[derive(Debug, Error)]
enum ReloadServerCertificateError {
    #[error("Unexpected material nature: {0}")]
    UnexpectedMaterialNature(#[from] MaterialError),
    #[error("Either the TLS chain or the private key is missing while the other is set")]
    MisconfiguredServerCertificates,
    #[error("Missing private key in the TLS private key file")]
    MissingPrivateKey,
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


impl State {
    pub fn reload_trust_anchors(&mut self, settings: &Settings) -> Result<(), ReloadTrustAnchorError> {
        if let Some(ref listener) = settings.listener {
            if let Some(ref client_ca) = listener.cacert_file {
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

                self.root_store = Some(Arc::new(roots));
            }
        }

        Ok(())
    }

    pub fn reload_server_certs(&mut self, settings: &Settings) -> Result<(), ReloadServerCertificateError> {
        if let Some(ref listener) = settings.listener {
            match (&listener.tls_chain, &listener.tls_privkey) {
                (Some(tls_chain), Some(tls_privkey)) => {
                    let mut tls_chain_file = BufReader::new(std::fs::File::open(&tls_chain)?);
                    let tls_chain_certs: Vec<_> = rustls_pemfile::read_all(&mut tls_chain_file)
                        .map(|item| item.map_err(|_| MaterialError::SectionParsingError).and_then(expect_certificate))
                        .collect::<Result<Vec<_>, _>>()?;
                    let (tls_private_key, _) = rustls_pemfile::read_one_from_slice(&std::fs::read(&tls_privkey)?).map_err(|_| ReloadServerCertificateError::PEMParsingError)?.ok_or(ReloadServerCertificateError::MissingPrivateKey)?;

                    self.server_certificates = Some(ServerCertificates {
                        cert_chain: tls_chain_certs, private_key: expect_private_key(tls_private_key)?
                    });
                },

                (None, None) => {
                    // No server TLS.
                    return Ok(());
                }

                _ => {
                    return Err(ReloadServerCertificateError::MisconfiguredServerCertificates);
                }
            }
        }

        Ok(())
    }

    pub fn reload_client_certs(&self) {
    }

    pub fn reload_acl_rules(&self) {
    }
}

pub struct Statistics {
    pub nr_ongoing_client_connections: AtomicUsize,
    pub nr_tcp_connections: AtomicUsize,
    pub nr_udp_connections: AtomicUsize
}

pub fn init(settings: &Settings) -> Result<State, InitError> {
    let mut state = State {
        default_backend: None,
        acl_rules: crate::acl::load_rules_from_file(&settings.filter_acl_rules_path.clone().unwrap()).unwrap(),
        root_store: None,
        client_cert_resolver: None,
        server_certificates: None,
    };

    // Load server certificates and trust anchors for the first time.
    state.reload_server_certs(settings)?;
    state.reload_trust_anchors(settings)?;

    Ok(state)
}
