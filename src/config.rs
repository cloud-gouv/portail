use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use chrono::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct BackendSettings {
    pub target_address: SocketAddr,
    /// Whether this backend requires a TLS connection with a client certificate.
    #[serde(default)]
    pub identity_aware: bool
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
    #[serde(default)]
    pub tcp_nodelay: bool,

    /// List of backends to which we can route proxy queries.
    pub backends: HashMap<String, BackendSettings>,

    /// Settings for the workload socket (e.g. this is where clients connect to, e.g. Firefox or
    /// another instance of this proxy via routing)
    pub listener: ListenSettings,
    /// Settings for connecting to other proxy instances or websites via client certificate
    /// authentication.
    pub escaper: EscapeSettings,
}

pub fn init() -> Settings {
    toml::from_slice(&std::fs::read("./config.toml").expect("Failed to read config file")).expect("Failed to parse config file")
}
