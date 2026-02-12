use std::sync::{Arc, atomic::AtomicUsize};

use crate::{config::Settings, pkcs11::PKCS11ClientCertResolver};

///! Contains the state of the application and various state transitions APIs.

pub struct State {
    pub default_backend: Option<String>,
    pub acl_rules: Vec<crate::acl::ACLRule>,
    pub root_store: Option<Arc<tokio_rustls::rustls::RootCertStore>>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
}

impl State {
    pub fn reload_trust_anchors(&self) {
    }

    /// This loads (first time) or reloads (reload or state deserialization) the client certificate
    /// resolver to initiate outbound connection based on the new settings.
    pub fn reload_client_certs(&mut self, settings: &Settings) {
        if let Some(ref escaper) = settings.escaper {
            self.client_cert_resolver = if let Some(ref pkcs11_library) = escaper.pkcs11_library {
                // TODO: add a proper error handling here that doesn't corrupt the state ideally.
                Some(Arc::new(PKCS11ClientCertResolver::new(None,
                pkcs11_library.as_os_str()
                ).unwrap()))
            } else {
                // Try to see if we can use usual certificate files here.
                // Otherwise, bail out.
                None
            };
        }
    }

    pub fn reload_acl_rules(&self) {
    }
}

pub struct Statistics {
    pub nr_ongoing_client_connections: AtomicUsize,
    pub nr_tcp_connections: AtomicUsize,
    pub nr_udp_connections: AtomicUsize
}

pub fn init(settings: &Settings) -> State {
    State {
        default_backend: None,
        acl_rules: crate::acl::load_rules_from_file(&settings.filter_acl_rules_path.clone().unwrap()).unwrap(),
        root_store: None,
        client_cert_resolver: None
    }
}
