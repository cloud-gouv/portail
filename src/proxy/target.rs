use std::{fmt, net::SocketAddr};

use http::uri::Authority;
use thiserror::Error;

use crate::proxy::host::{CanonicalHost, CanonicalHostError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAuthority {
    pub host: CanonicalHost,
    pub port: u16,
    pub explicit_port: bool,
}

#[derive(Debug, Error)]
pub enum TargetAuthorityError {
    #[error("The authority has no host")]
    MissingHost,
    #[error(transparent)]
    InvalidHost(#[from] CanonicalHostError),
}

impl TargetAuthority {
    pub fn parse(authority: &Authority, default_port: u16) -> Result<Self, TargetAuthorityError> {
        if authority.host().is_empty() {
            return Err(TargetAuthorityError::MissingHost);
        }

        Ok(Self {
            host: CanonicalHost::parse(authority.host())?,
            port: authority.port_u16().unwrap_or(default_port),
            explicit_port: authority.port_u16().is_some(),
        })
    }

    pub fn from_host_port(host: &str, port: u16) -> Result<Self, TargetAuthorityError> {
        Ok(Self {
            host: CanonicalHost::parse(host)?,
            port,
            explicit_port: true,
        })
    }

    pub fn from_socket_addr(address: SocketAddr) -> Result<Self, TargetAuthorityError> {
        let host = match address {
            SocketAddr::V4(address) => address.ip().to_string(),
            SocketAddr::V6(address) => format!("[{}]", address.ip()),
        };

        Self::from_host_port(&host, address.port())
    }
}

impl fmt::Display for TargetAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = self.host.as_str();

        if host.contains(':') && !host.starts_with('[') {
            write!(formatter, "[{host}]:{}", self.port)
        } else {
            write!(formatter, "{host}:{}", self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_with_explicit_port() {
        let authority: Authority = "example.com:8443".parse().unwrap();
        let target = TargetAuthority::parse(&authority, 443).unwrap();

        assert_eq!(target.host.as_str(), "example.com");
        assert_eq!(target.port, 8443);
        assert!(target.explicit_port);
        assert_eq!(target.to_string(), "example.com:8443");
    }

    #[test]
    fn parses_host_with_default_port() {
        let authority: Authority = "Example.COM.".parse().unwrap();
        let target = TargetAuthority::parse(&authority, 443).unwrap();

        assert_eq!(target.host.as_str(), "example.com");
        assert_eq!(target.port, 443);
        assert!(!target.explicit_port);
        assert_eq!(target.to_string(), "example.com:443");
    }

    #[test]
    fn formats_ipv6_with_brackets() {
        let target = TargetAuthority::from_socket_addr("[::1]:443".parse().unwrap()).unwrap();
        assert_eq!(target.to_string(), "[::1]:443");
    }
}
