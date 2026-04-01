use std::{fmt::Display, net::SocketAddr};

#[allow(clippy::large_enum_variant)]
pub enum InboundStream {
    TcpStream(tokio::net::TcpStream),
    TlsStream(tokio_rustls::TlsStream<tokio::net::TcpStream>),
}

#[allow(dead_code)]
enum ProxyProtocol {
    Socks5,
    Http1,
    Http2,
    Http3,
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Domain(String, u16),
    IP(SocketAddr),
}

impl TargetAddr {
    pub fn into_string_and_port(self) -> (String, u16) {
        match self {
            Self::Domain(domain, port) => (domain, port),
            Self::IP(ip) => (ip.ip().to_string(), ip.port()),
        }
    }
}

impl Display for TargetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Domain(domain, port) => f.write_fmt(format_args!("{}:{}", domain, port)),
            Self::IP(ip) => f.write_fmt(format_args!("{}", ip)),
        }
    }
}

impl From<fast_socks5::util::target_addr::TargetAddr> for TargetAddr {
    fn from(value: fast_socks5::util::target_addr::TargetAddr) -> Self {
        match value {
            fast_socks5::util::target_addr::TargetAddr::Ip(socket_addr) => Self::IP(socket_addr),
            fast_socks5::util::target_addr::TargetAddr::Domain(domain, port) => {
                Self::Domain(domain, port)
            }
        }
    }
}

pub struct TargetContext {
    pub initial_target: TargetAddr,
    pub resolved_target: Option<TargetAddr>,
}

#[derive(Debug, Clone)]
pub struct InitialRequestContext {
    pub client_address: SocketAddr,
    pub acl_ctx: crate::acl::OwnedEvaluationContext,
}

#[derive(Debug, Clone)]
pub struct LocalRequestContext<'s> {
    #[allow(dead_code)]
    pub client_address: &'s SocketAddr,
    pub acl_ctx: crate::acl::EvaluationContext<'s>,
}

impl InitialRequestContext {
    pub fn new(client_address: SocketAddr) -> Self {
        Self {
            client_address,
            acl_ctx: crate::acl::OwnedEvaluationContext::empty(),
        }
    }

    pub fn as_local<'s>(&'s self) -> LocalRequestContext<'s> {
        LocalRequestContext {
            client_address: &self.client_address,
            acl_ctx: self.acl_ctx.fork(),
        }
    }
}
