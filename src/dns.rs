use std::sync::Arc;
use std::{net::IpAddr, time::Duration};

use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts},
    net::NetError,
    net::runtime::TokioRuntimeProvider,
};
use thiserror::Error;
use tokio::{net::lookup_host, time::timeout};

use crate::config::DnsSettings;

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("dns lookup failed for {host}")]
    LookupFailed {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no dns records for {host}")]
    NoRecords { host: String },

    #[error("dns lookup timed out for {host}")]
    TimedOut { host: String },
}

pub struct DnsResolver {
    hickory: Option<TokioResolver>,
    timeout: Duration,
}

/// If DNS settings are provided, uses Hickory DNS resolver. Otherwise, uses the system resolver.
impl DnsResolver {
    pub fn from_settings(dns: &DnsSettings) -> anyhow::Result<Arc<Self>> {
        let hickory = if dns.resolvers.is_empty() {
            None
        } else {
            Some(build_hickory(&dns.resolvers, dns.timeout)?)
        };

        Ok(Arc::new(Self {
            hickory,
            timeout: dns.timeout,
        }))
    }

    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let ips: Vec<IpAddr> = if let Some(resolver) = &self.hickory {
            let lookup = resolver.lookup_ip(host).await.map_err(|err| match err {
                NetError::Timeout => DnsError::TimedOut {
                    host: host.to_owned(),
                },
                _ => DnsError::LookupFailed {
                    host: host.to_owned(),
                    source: std::io::Error::other(err),
                },
            })?;
            lookup.iter().collect()
        } else {
            // lookup_host is a wrapper around std::net::ToSocketAddrs (which is just getaddrinfo):
            // https://github.com/tokio-rs/tokio/blob/d87569164fb61145e79e7ffe0b25783569cc8f93/tokio/src/net/lookup_host.rs#L32
            //
            // It is used to resolve addresses by both fast-socks5 and tokio:
            // https://github.com/dizda/fast-socks5/blob/acb847616ec44b6c2d6cdaddeba090d18c6c5d5c/src/util/target_addr.rs#L61
            // https://github.com/tokio-rs/tokio/blob/d87569164fb61145e79e7ffe0b25783569cc8f93/tokio/src/net/tcp/stream.rs#L119
            timeout(self.timeout, lookup_host((host, 0)))
                .await
                .map_err(|_| DnsError::TimedOut {
                    host: host.to_owned(),
                })?
                .map_err(|source| DnsError::LookupFailed {
                    host: host.to_owned(),
                    source,
                })?
                .map(|addr| addr.ip())
                .collect()
        };

        if ips.is_empty() {
            return Err(DnsError::NoRecords {
                host: host.to_owned(),
            });
        }

        Ok(ips)
    }
}

fn build_hickory(servers: &[IpAddr], timeout: Duration) -> anyhow::Result<TokioResolver> {
    let name_servers: Vec<NameServerConfig> = servers
        .iter()
        .copied()
        .map(NameServerConfig::udp_and_tcp)
        .collect();
    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut opts = ResolverOpts::default();
    opts.timeout = timeout;
    // Default is Ipv6AndIpv4:
    // https://docs.rs/hickory-resolver/0.26.1/src/hickory_resolver/config.rs.html#709
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build DNS resolver: {err}"))
}
