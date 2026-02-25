use std::sync::{Arc, atomic::AtomicUsize};

use crate::config::Settings;

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

pub fn init(settings: &Settings) -> State {
    State {
        default_backend: settings.default_backend.clone(),
        acl_rules: crate::acl::load_rules_from_file(&settings.filter_acl_rules_path.clone().unwrap()).unwrap(),
        root_store: None,
        client_cert_resolver: None
    }
}
