//! Peer certificate identity extraction for mTLS clients.

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial: String,
    pub san_dns: HashSet<String>,
    pub san_uri: HashSet<String>,
    pub san_email: HashSet<String>,
    pub san_ip: HashSet<String>,
    pub not_before: i64,
    pub not_after: i64,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("The certificate cannot be parsed: {0}")]
    ParseError(String),
}

impl PeerIdentity {
    pub fn from_der(der: &[u8]) -> Result<Self, IdentityError> {
        let (_, certificate) = X509Certificate::from_der(der)
            .map_err(|error| IdentityError::ParseError(error.to_string()))?;

        let mut san_dns = HashSet::new();
        let mut san_uri = HashSet::new();
        let mut san_email = HashSet::new();
        let mut san_ip = HashSet::new();

        if let Some(extension) = certificate
            .subject_alternative_name()
            .map_err(|error| IdentityError::ParseError(error.to_string()))?
        {
            for name in &extension.value.general_names {
                match name {
                    GeneralName::DNSName(value) => {
                        san_dns.insert((*value).to_owned());
                    }
                    GeneralName::URI(value) => {
                        san_uri.insert((*value).to_owned());
                    }
                    GeneralName::RFC822Name(value) => {
                        san_email.insert((*value).to_owned());
                    }
                    GeneralName::IPAddress(value) if value.len() == 4 => {
                        san_ip.insert(
                            Ipv4Addr::new(value[0], value[1], value[2], value[3]).to_string(),
                        );
                    }
                    GeneralName::IPAddress(value) if value.len() == 16 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(value);
                        san_ip.insert(Ipv6Addr::from(octets).to_string());
                    }
                    _ => {}
                }
            }
        }

        let validity = certificate.validity();

        Ok(Self {
            subject_cn: common_name(&certificate, true),
            issuer_cn: common_name(&certificate, false),
            serial: certificate.serial.to_string(),
            san_dns,
            san_uri,
            san_email,
            san_ip,
            not_before: validity.not_before.timestamp(),
            not_after: validity.not_after.timestamp(),
        })
    }
}

fn common_name(certificate: &X509Certificate<'_>, subject: bool) -> Option<String> {
    let name = if subject {
        certificate.subject()
    } else {
        certificate.issuer()
    };

    name.iter_common_name()
        .next()
        .and_then(|name| name.as_str().ok())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use rustls_pki_types::{CertificateDer, pem::PemObject};

    use super::*;

    fn certificate() -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(include_bytes!(
            "../../nix/tests/certs/portail.corp/portail.corp.example.com.cert.pem"
        ))
        .expect("fixture certificate")
    }

    #[test]
    fn parses_common_name_and_sans() {
        let identity = PeerIdentity::from_der(certificate().as_ref()).expect("parse identity");

        assert_eq!(
            identity.subject_cn.as_deref(),
            Some("portail.corp.example.com")
        );
        assert!(identity.san_dns.contains("portail.corp.example.com"));
        assert!(!identity.serial.is_empty());
        assert!(identity.not_before < identity.not_after);
    }

    #[test]
    fn rejects_malformed_certificate() {
        assert!(PeerIdentity::from_der(b"not a certificate").is_err());
    }
}
