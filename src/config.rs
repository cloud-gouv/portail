use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
pub use tokio_rustls::rustls::pki_types::ServerName;

#[derive(Debug, Clone)]
pub struct KnownBackend {
    pub target_address: SocketAddr,
    /// Whether this backend requires a TLS connection with a client certificate.
    pub identity_aware: bool,
    /// TLS server name for identity-aware outbound connections.
    ///
    /// When omitted in config, the target address IP is used.
    pub tls_server_name: ServerName<'static>,
}

#[derive(Debug, Clone)]
pub enum BackendSettings {
    /// This is a backend (dynamic or not) which has been resolved to a backend.
    KnownBackend(KnownBackend),
    /// This is a dynamic backend for which we do not know the target address yet.
    UnresolvedBackend,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
struct RawBackendSettings {
    target_address: Option<SocketAddr>,
    #[serde(default)]
    dynamic: bool,
    #[serde(default)]
    identity_aware: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls_server_name: Option<String>,
}

impl<'de> Deserialize<'de> for BackendSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = RawBackendSettings::deserialize(deserializer)?;

        if !s.dynamic && s.target_address.is_none() {
            return Err(de::Error::custom(
                "Target address cannot be omitted if the backend is not dynamic",
            ));
        }

        match s.target_address {
            Some(tgt_address) => {
                let tls_server_name = match s.tls_server_name {
                    Some(str) => ServerName::try_from(str).map_err(|e| {
                        de::Error::custom(format!("invalid tls_server_name: {e:?}"))
                    })?,
                    None => ServerName::from(tgt_address.ip()),
                };

                Ok(BackendSettings::KnownBackend(KnownBackend {
                    target_address: tgt_address,
                    identity_aware: s.identity_aware,
                    tls_server_name,
                }))
            }
            None => Ok(BackendSettings::UnresolvedBackend),
        }
    }
}

impl Serialize for BackendSettings {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::UnresolvedBackend => RawBackendSettings {
                target_address: None,
                identity_aware: false,
                dynamic: true,
                tls_server_name: None,
            },
            Self::KnownBackend(KnownBackend {
                target_address,
                identity_aware,
                tls_server_name,
            }) => {
                let tls_default = ServerName::from(target_address.ip());
                let tls_server_name = if *tls_server_name == tls_default {
                    None
                } else {
                    Some(tls_server_name.to_str().into_owned())
                };

                RawBackendSettings {
                    target_address: Some(*target_address),
                    identity_aware: *identity_aware,
                    dynamic: false,
                    tls_server_name,
                }
            }
        }
        .serialize(serializer)
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

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RPCSettings {
    /// Administrative groups are allowed to call admin RPCs such as UpdateDynamicBackend.
    /// They can disable the proxy functionality or bypass it by redirecting the
    /// dynamic backend to an attacker-controlled target.
    #[serde(default)]
    pub admin_groups: Vec<String>,
    /// Trusted groups are allowed to call write RPC such as SetDefaultBackend or Reload.
    /// They cannot disable the proxy functionality nonetheless.
    #[serde(default)]
    pub trusted_groups: Vec<String>,
}

fn default_dns_timeout() -> Duration {
    Duration::from_secs(5)
}

#[serde_with::serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct DnsSettings {
    /// Resolvers for direct-exit name resolution.
    /// When empty, the system resolver is used instead.
    #[serde(default)]
    pub resolvers: Vec<std::net::IpAddr>,

    /// Timeout for DNS lookups.
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    #[serde(default = "default_dns_timeout")]
    pub timeout: Duration,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            resolvers: Vec::new(),
            timeout: default_dns_timeout(),
        }
    }
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
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub request_timeout: Duration,

    /// Whether to disable the TCP Nagle optimisation on the proxy side.
    #[serde(default)]
    pub tcp_nodelay: bool,

    /// Whether to set a default upstream.
    pub default_backend: Option<String>,

    /// DNS settings for direct-exit name resolution.
    #[serde(default)]
    pub dns: DnsSettings,

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

    /// Settings for the local RPC (authorization).
    #[serde(default)]
    pub rpc: RPCSettings,
}

pub fn init(config_path: &Path) -> Settings {
    toml::from_slice(&std::fs::read(config_path).expect("Failed to read config file"))
        .expect("Failed to parse config file")
}
