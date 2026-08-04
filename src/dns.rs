use std::cmp::Ordering::Equal;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{net::IpAddr, time::Duration};

use futures::future::select_ok;
use hickory_resolver::{
    TokioResolver,
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    net::NetError,
    net::runtime::TokioRuntimeProvider,
};
use thiserror::Error;
use tokio::{net::TcpStream, net::lookup_host, time::timeout};

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

/// Happy Eyeballs v2 constants per RFC 8305.
/// Minimum delay between successive connection attempts within the same address
/// family, to avoid flooding the network stack with SYNs to unreachable hosts.
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(250);

#[derive(Debug, Error)]
pub enum HappyEyeballsError {
    #[error("DNS resolution failed: {0}")]
    Dns(#[from] DnsError),

    #[error("all connection attempts to {host}:{port} failed")]
    AllFailed { host: String, port: u16 },

    #[error("no addresses to connect to for {host}:{port}")]
    /// No addresses were available for the hostname.
    #[allow(dead_code)]
    NoAddresses { host: String, port: u16 },
}

/// Resolves `host` to addresses, then races IPv6 and IPv4 connection attempts
/// per RFC 8305 (Happy Eyeballs v2).
///
/// Returns the first successfully established `TcpStream` together with the
/// remote `SocketAddr` it connected to.
pub async fn happy_eyeballs_connect(
    resolver: &DnsResolver,
    host: &str,
    port: u16,
    connect_timeout: Duration,
    tcp_nodelay: bool,
) -> Result<(TcpStream, SocketAddr), HappyEyeballsError> {
    let ips = resolver.lookup(host).await?;
    let (stream, addr) = happy_eyeballs_connect_addrs(ips, port, connect_timeout)
        .await
        .map_err(|_| HappyEyeballsError::AllFailed {
            host: host.to_owned(),
            port,
        })?;
    if tcp_nodelay {
        // Best-effort: nodelay failure should not fail the connection.
        let _ = stream.set_nodelay(true);
    }
    Ok((stream, addr))
}

/// Core Happy Eyeballs v2 algorithm: given already-resolved addresses, race
/// connection attempts across address families.
///
/// This is separated from [`happy_eyeballs_connect`] so it can be tested
/// without a DNS resolver.
async fn happy_eyeballs_connect_addrs(
    // TODO: make this a stream later on once hickory supports it.
    addrs: Vec<IpAddr>,
    port: u16,
    connect_timeout: Duration,
) -> Result<(TcpStream, SocketAddr), Vec<io::Error>> {
    if addrs.is_empty() {
        return Err(vec![]);
    }

    let addrs = sort_destinations(addrs, AddressFamilyPreference::Ipv6First);

    // TODO: obtain temporary RTTs information on regular targets in-memory to better influence
    // destination selection.

    // Each task sends its success here. First one wins.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<io::Result<(TcpStream, SocketAddr)>>(1);

    let handle = tokio::spawn(try_connect_family(addrs, port, connect_timeout, tx));

    // Wait for the first successful connection.
    let result = match rx.recv().await {
        Some(Ok((stream, addr))) => Ok((stream, addr)),
        Some(Err(_)) => match rx.recv().await {
            Some(Ok((stream, addr))) => Ok((stream, addr)),
            _ => Err(vec![]),
        },
        None => Err(vec![]),
    };

    // Cancel the losing task(s).
    handle.abort();

    result
}

/// Try connecting to each address in `addrs` sequentially.
///
/// Sends the first successful `(TcpStream, SocketAddr)` through `tx` and
/// returns. If all addresses fail, the function returns silently.
///
/// The first attempt begins after `initial_delay`. Subsequent attempts within
/// the family are spaced by [`CONNECTION_ATTEMPT_DELAY`].
async fn try_connect_family(
    addrs: Vec<IpAddr>,
    port: u16,
    connect_timeout: Duration,
    tx: tokio::sync::mpsc::Sender<io::Result<(TcpStream, SocketAddr)>>,
) {
    if addrs.is_empty() {
        return;
    }

    let cancel_handle = tokio_util::sync::CancellationToken::new();

    let connect_futures: Vec<_> = addrs
        .into_iter()
        .enumerate()
        .map(|(i, ip)| {
            let addr = SocketAddr::new(ip, port);
            let cancel_handle = cancel_handle.clone();
            async move {
                // Stagger the start of each connection attempt, the first one gets zero
                // staggering.
                tokio::select! {
                    _ = tokio::time::sleep(CONNECTION_ATTEMPT_DELAY * i as u32) => {},
                    _ = cancel_handle.cancelled() => {
                        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "cancelled due to prior success"));
                    }
                }

                tokio::select! {
                    result = timeout(connect_timeout, TcpStream::connect(addr)) => {
                        match result {
                            Ok(Ok(stream)) => {
                                // Success! Signal cancellation to all other tasks
                                cancel_handle.cancel();
                                Ok((stream, addr))
                            }
                            Ok(Err(e)) => Err(e),
                            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "timeout")),
                        }
                    }

                    _ = cancel_handle.cancelled() => {
                        // Cancelled during connection attempt
                        Err(io::Error::new(io::ErrorKind::ConnectionAborted, "cancelled due to prior success"))
                    }
                }
            }
        })
        .collect();

    // `select_ok` requires pinned futures.
    let pinned_futures: Vec<_> = connect_futures.into_iter().map(Box::pin).collect();

    // Race all connections, get the first successful one
    match select_ok(pinned_futures).await {
        Ok(((stream, addr), _index)) => {
            let _ = tx.send(Ok((stream, addr))).await;
        }
        Err(_) => {
            // All connections failed.
        }
    }

    // All addresses failed. The sender is dropped implicitly.
    // If this was the last sender, the receiver will be disconnected.
}

#[derive(Debug, Clone, Copy)]
enum AddressFamilyPreference {
    Ipv6First,
    #[allow(dead_code)]
    Ipv4First,
}

/// Sort destination addresses per RFC 6724 §6, then interleave families one-by-one so connection
/// attempts alternate between address families.
///
/// # Algorithm
///
/// 1. Split addresses into 2 families groups.
/// 2. Sort each group independently per RFC 6724 rules.
/// 3. Interleave starting with the preferred family: `pref[0], other[0], pref[1], other[1], …`.
///
/// This gives a head start to preferred family (to `CONNECTION_ATTEMPT_DELAY`).
fn sort_destinations(addrs: Vec<IpAddr>, preference: AddressFamilyPreference) -> Vec<IpAddr> {
    let (mut preferred, mut other): (Vec<IpAddr>, Vec<IpAddr>) = match preference {
        AddressFamilyPreference::Ipv6First => addrs.into_iter().partition(|ip| ip.is_ipv6()),
        AddressFamilyPreference::Ipv4First => addrs.into_iter().partition(|ip| ip.is_ipv4()),
    };

    preferred.sort_by(rfc6724_compare);
    other.sort_by(rfc6724_compare);

    let mut result = Vec::with_capacity(preferred.len() + other.len());

    let mut p = preferred.into_iter();
    let mut o = other.into_iter();

    loop {
        match (p.next(), o.next()) {
            (Some(a), Some(b)) => {
                result.push(a);
                result.push(b);
            }
            (Some(a), None) => result.push(a),
            (None, Some(b)) => result.push(b),
            (None, None) => break,
        };
    }

    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Scope {
    InterfaceLocal = 0x1,
    LinkLocal = 0x2,
    #[allow(dead_code)]
    AdminLocal = 0x4,
    SiteLocal = 0x5,
    OrgLocal = 0x8,
    Global = 0xe,
}

fn rfc6724_compare(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    // R1: TODO: Avoid unusable destinations. We need to compute reachability. Doable via netlink.
    // R2: TODO: Prefer matching scope. We need to compute source addresses.

    // R8: prefer smaller scope.

    // A smaller-scope destination is "closer", thus preferred.
    let sa = ip_scope(a);
    let sb = ip_scope(b);
    if sa != sb {
        return sa.cmp(&sb);
    }

    // R3: not applicable.
    // R4: not applicable.
    // R5: not applicable (requires a policy table which we don't have).
    // R6: this is the interleave step.
    // R7: not important.
    // R9: longest prefix matching.
    // R10: OK.

    Equal
}

fn ip_scope(addr: &IpAddr) -> Scope {
    match addr {
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                Scope::InterfaceLocal
            } else if v6.segments()[0] & 0xffc0 == 0xfe80 {
                Scope::LinkLocal
            } else if v6.segments()[0] & 0xffc0 == 0xfec0 {
                Scope::SiteLocal
            } else if v6.segments()[0] & 0xfe00 == 0xfc00 {
                Scope::OrgLocal
            } else {
                Scope::Global
            }
        }
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Scope::InterfaceLocal
            } else if v4.is_link_local() {
                Scope::LinkLocal
            } else if v4.is_private() {
                Scope::SiteLocal
            } else {
                Scope::Global
            }
        }
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

    TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build DNS resolver: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Start a TCP listener on localhost, return its SocketAddr.
    async fn bind_ephemeral() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
    }

    /// Spawn an acceptor that accepts one connection and immediately drops it.
    fn spawn_accept_one(listener: TcpListener) {
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
    }

    #[tokio::test]
    async fn single_ipv4_connect_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_accept_one(listener);

        let result =
            happy_eyeballs_connect_addrs(vec![addr.ip()], addr.port(), Duration::from_secs(2))
                .await;

        assert!(result.is_ok(), "expected connection to succeed");
        let (_stream, connected_addr) = result.unwrap();
        assert_eq!(connected_addr.port(), addr.port());
    }

    #[tokio::test]
    async fn single_ipv4_connect_failure() {
        // Use a port where nothing is listening.
        // Bind to get a port, then drop the listener so it's closed.
        let addr = bind_ephemeral().await;
        // addr is now free (listener dropped)

        let result =
            happy_eyeballs_connect_addrs(vec![addr.ip()], addr.port(), Duration::from_millis(200))
                .await;

        assert!(result.is_err(), "expected connection to fail");
    }

    #[tokio::test]
    async fn empty_address_list() {
        let result = happy_eyeballs_connect_addrs(vec![], 80, Duration::from_secs(2)).await;

        assert!(result.is_err(), "expected empty address list to error");
    }

    #[tokio::test]
    async fn happy_eyeballs_falls_back_to_ipv4_when_ipv6_unreachable() {
        // Set up a real IPv4 listener.
        let v4_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let v4_addr = v4_listener.local_addr().unwrap();
        spawn_accept_one(v4_listener);

        // Use an unreachable IPv6 address (::1 on a random high port with
        // nothing listening).  We put it *first* so a naive sequential
        // implementation would time out on it before trying IPv4.
        let unreachable_v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);

        let addrs = vec![unreachable_v6, v4_addr.ip()];
        let start = tokio::time::Instant::now();

        let result =
            happy_eyeballs_connect_addrs(addrs, v4_addr.port(), Duration::from_millis(500)).await;

        let elapsed = start.elapsed();

        assert!(
            result.is_ok(),
            "expected Happy Eyeballs to fall back to IPv4"
        );
        let (_stream, connected_addr) = result.unwrap();
        assert_eq!(connected_addr.ip(), v4_addr.ip());
        assert_eq!(connected_addr.port(), v4_addr.port());

        // The connect should succeed roughly after RESOLUTION_DELAY + connect time,
        // certainly faster than waiting for the full IPv6 timeout sequentially.
        // With sequential: 500ms (IPv6 timeout) + connect time > 500ms.
        // With Happy Eyeballs: ~250ms (delay) + connect time < 500ms.
        // We use a bound with extra space to avoid flakiness.
        assert!(
            elapsed < Duration::from_millis(800),
            "Happy Eyeballs should connect faster than sequential: took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn happy_eyeballs_ipv6_succeeds_immediately() {
        // When IPv6 is reachable, it should win immediately (no resolution delay
        // penalty).
        let v6_listener = TcpListener::bind("[::1]:0").await.unwrap();
        let v6_addr = v6_listener.local_addr().unwrap();
        spawn_accept_one(v6_listener);

        let start = tokio::time::Instant::now();

        let result = happy_eyeballs_connect_addrs(
            vec![v6_addr.ip()],
            v6_addr.port(),
            Duration::from_secs(2),
        )
        .await;

        let elapsed = start.elapsed();

        assert!(result.is_ok(), "expected IPv6 connection to succeed");
        // Should connect almost immediately, well under 100ms locally.
        assert!(
            elapsed < Duration::from_millis(200),
            "IPv6 connect should be fast, took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn multiple_ipv4_first_unreachable_second_reachable() {
        // Within a single family, the algorithm should try the second address
        // after the first fails.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();
        spawn_accept_one(listener);

        // Get a dead port — bind then immediately drop.
        let dead_addr = bind_ephemeral().await;

        let addrs = vec![dead_addr.ip(), good_addr.ip()];

        let result =
            happy_eyeballs_connect_addrs(addrs, good_addr.port(), Duration::from_millis(300)).await;

        assert!(
            result.is_ok(),
            "expected fallback to second address within same family"
        );
        let (_stream, connected_addr) = result.unwrap();
        assert_eq!(connected_addr.ip(), good_addr.ip());
    }

    #[tokio::test]
    async fn cancellation_cancels_pending_connections() {
        // This test verifies that when one connection succeeds, it immediately finishes.

        // Create a slow listener that accepts after a delay
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a slow acceptor (accepts after 1000ms)
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2000)).await;
            let _ = listener.accept().await;
        });

        // Create a second listener that accepts immediately
        let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        spawn_accept_one(listener2);

        let addrs = vec![addr.ip(), addr2.ip()];

        let start = tokio::time::Instant::now();
        let result =
            happy_eyeballs_connect_addrs(addrs, addr2.port(), Duration::from_secs(5)).await;
        let elapsed = start.elapsed();

        assert!(result.is_ok(), "connection should succeed");

        // The second connection (addr2) should succeed quickly.
        // The first connection attempt should be cancelled when the second succeeds.
        // Since addr2 is reachable immediately, the total time should be short.
        assert!(
            elapsed < Duration::from_millis(200),
            "Should connect quickly without waiting for slow connection: took {elapsed:?}"
        );
    }
}
