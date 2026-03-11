use chrono::Duration;
use std::{
    collections::HashMap,
    fmt::Display,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", tag = "type")]
pub enum BackendSettings {
    /// For identity-aware proxies (i.e. TLS with client certificates)
    IdentityAware { target_address: SocketAddr },

    /// For proxies behind SSH
    SSH {
        target_address: SocketAddr,
        proxy_address: SocketAddr,
    },

    /// For direct proxy without any specific identity awareness (i.e. no TLS with client
    /// certificates)
    #[serde(untagged)]
    Direct { target_address: SocketAddr },
}

impl Display for BackendSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IdentityAware { target_address } => f.write_fmt(format_args!(
                "<identity-aware direct backend to {}>",
                target_address
            )),
            Self::Direct { target_address } => {
                f.write_fmt(format_args!("<direct backend to {}>", target_address))
            }
            Self::SSH {
                target_address,
                proxy_address,
            } => f.write_fmt(format_args!(
                "<backend {} over SSH to {}>",
                proxy_address, target_address
            )),
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ListenSettings {
    /// The CA used to validate inbound client authentication via client certs
    pub cacert_file: Option<PathBuf>,
    /// The TLS key material to present server facing TLS certificates
    pub tls_privkey: Option<PathBuf>,
    pub tls_chain: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct EscapeSettings {
    /// Client certificates configuration
    pub cacert_file: Option<PathBuf>,
    pub tls_privkey: Option<PathBuf>,
    pub tls_certificate: Option<PathBuf>,
    pub pkcs11_uri: Option<String>,
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Settings {
    /// ACL rules for filtering
    pub filter_acl_rules_path: Option<PathBuf>,

    /// ACL rules to reduce the details of explaining why an access is blocked.
    pub explain_acl_rules_path: Option<PathBuf>,

    /// IP address communicated to get the UDP packets back
    pub public_address: Option<std::net::IpAddr>,

    /// Global generic options for proxying
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub request_timeout: Duration,

    /// Whether to disable the TCP Nagle optimisation on the proxy side.
    #[serde(default)]
    pub tcp_nodelay: bool,

    /// Whether to set a default upstream.
    pub default_backend: Option<String>,

    /// List of backends to which we can route proxy queries.
    #[serde(default)]
    pub backends: HashMap<String, BackendSettings>,

    /// Settings for the workload socket (e.g. this is where clients connect to, e.g. Firefox or
    /// another instance of this proxy via routing)
    /// If this is unset, there's no TLS on incoming connections.
    /// Use this when you are binding a local daemon.
    pub listener: Option<ListenSettings>,

    /// Settings for connecting to other proxy instances or websites via client certificate
    /// authentication.
    pub escaper: Option<EscapeSettings>,
}

pub fn init(config_path: &Path) -> Settings {
    toml::from_slice(&std::fs::read(config_path).expect("Failed to read config file"))
        .expect("Failed to parse config file")
}
