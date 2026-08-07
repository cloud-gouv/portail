use std::io::Cursor;

use tokio_rustls::rustls::{NamedGroup, ProtocolVersion, ServerConnection, SignatureScheme};
use tracing::debug;

use crate::proxy::protocols::HttpVersion;

/// TLS-specialized protocol decoding primitives.
/// Ideally, as much as possible of this should go into rustls.
use super::{DetectedProtocol, DetectionError};

fn map_alpn(alpn: &[u8]) -> Option<HttpVersion> {
    if alpn == super::ALPN_H2 {
        Some(HttpVersion::Http2_0)
    } else if alpn == super::ALPN_HTTP1_1 {
        Some(HttpVersion::Http1_1)
    } else {
        None
    }
}

/// From a rustls' server connection, extract all TLS related details, including negotiated ALPN
/// protocols.
pub fn from_tls_session(session: &ServerConnection) -> DetectedProtocol {
    let http_ver = if let Some(alpn) = session.alpn_protocol() {
        map_alpn(alpn).map(|s| vec![s])
    } else {
        None
    };

    DetectedProtocol::Tls(TlsInfo {
        version: session
            .protocol_version()
            .map(|proto| proto.into())
            .unwrap_or(TlsVersion::Other),
        alpn: http_ver,
        server_name_indication: session.server_name().map(|s| s.to_owned()),
        pqc_coverage: diagnose_pqc_readiness_from_server_session(session),
    })
}

/// Verify quickly if a TCP stream has a TLS prefix.
pub async fn has_tls_prefix(stream: &tokio::net::TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; 3];
    let n = stream.peek(&mut buf).await?;

    if n < 3 {
        return Ok(false);
    }

    Ok(buf[0] == 0x16 && buf[1] == 0x03)
}

/// Parses the initial bytes of a TLS handshake to extract all TLS extensions
/// that might be relevant.
///
/// Of interest:
/// - Server Name Indication
/// - Whether this connection is protected by hybrid PQC cryptography.
/// - actual TLS version
///
/// We may add more extensions to expose it to the end user.
pub fn parse_tls_client_hello(peeked: &[u8]) -> Result<DetectedProtocol, DetectionError> {
    let mut acceptor = tokio_rustls::rustls::server::Acceptor::default();

    let mut cursor = Cursor::new(peeked);
    if acceptor.read_tls(&mut cursor).is_err() {
        return Ok(DetectedProtocol::Unknown);
    }

    match acceptor.accept() {
        Ok(None) => Err(DetectionError::MoreDataRequired(None)),
        Ok(Some(accepted)) => extract_client_hello(accepted.client_hello()),
        Err((err, alert)) => {
            debug!(err = ?err, alert = ?alert, "TLS client hello extraction failed");
            println!("{:?} {:?}", err, alert);
            Err(DetectionError::Inconclusive)
        }
    }
}

fn extract_client_hello(
    client_hello: tokio_rustls::rustls::server::ClientHello,
) -> Result<DetectedProtocol, DetectionError> {
    let sni = client_hello.server_name();

    Ok(DetectedProtocol::Tls(TlsInfo {
        version: TlsVersion::Tls12, // FIXME: get the real version.
        server_name_indication: sni.map(|s| s.to_owned()),
        alpn: client_hello
            .alpn()
            .map(|values| values.filter_map(map_alpn).collect()),
        pqc_coverage: diagnose_pqc_readiness_from_client_hello(&client_hello),
    }))
}

fn extract_strongest_scheme(schemes: &[PqcScheme]) -> Option<&PqcScheme> {
    let hybrid = schemes
        .iter()
        .find(|sch| matches!(sch, PqcScheme::Hybrid(_)));
    if hybrid.is_some() {
        return hybrid;
    }

    let pure = schemes.iter().find(|sch| matches!(sch, PqcScheme::Pure(_)));
    if pure.is_some() {
        return pure;
    }

    let classical = schemes
        .iter()
        .find(|sch| matches!(sch, PqcScheme::Classical));
    if classical.is_some() {
        return classical;
    }

    None
}

fn diagnose_pqc_readiness_from_client_hello(
    client_hello: &tokio_rustls::rustls::server::ClientHello,
) -> PqcDiagnostic {
    let strongest_kex = client_hello
        .named_groups()
        .map(|groups| {
            let schemes: Vec<_> = groups.iter().map(PqcScheme::from_named_group).collect();

            extract_strongest_scheme(&schemes)
                .cloned()
                .unwrap_or(PqcScheme::Unknown)
        })
        .unwrap_or(PqcScheme::Unknown);

    let sig_schemes: Vec<_> = client_hello
        .signature_schemes()
        .into_iter()
        .map(PqcScheme::from_signature_scheme)
        .collect();

    PqcDiagnostic {
        signature_scheme: extract_strongest_scheme(&sig_schemes)
            .cloned()
            .unwrap_or(PqcScheme::Unknown),
        kex_scheme: strongest_kex,
    }
}

fn diagnose_pqc_readiness_from_server_session(session: &ServerConnection) -> PqcDiagnostic {
    let chosen_kex = session
        .negotiated_key_exchange_group()
        .map(|kex| PqcScheme::from_named_group(&kex.name()))
        .unwrap_or(PqcScheme::Unknown);

    PqcDiagnostic {
        signature_scheme: PqcScheme::Unknown,
        kex_scheme: chosen_kex,
    }
}

#[derive(Debug, Clone, Copy)]
pub enum TlsVersion {
    Tls12,
    Tls13,
    Other,
}

impl From<ProtocolVersion> for TlsVersion {
    fn from(value: ProtocolVersion) -> Self {
        match value {
            ProtocolVersion::TLSv1_2 | ProtocolVersion::DTLSv1_2 => TlsVersion::Tls12,
            ProtocolVersion::TLSv1_3 | ProtocolVersion::DTLSv1_3 => TlsVersion::Tls13,
            // aka. bad values.
            _ => TlsVersion::Other,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PqcScheme {
    Classical,
    Hybrid(String),
    Pure(String),
    Unknown,
}

impl PqcScheme {
    fn from_named_group(group: &NamedGroup) -> Self {
        match group {
            NamedGroup::X25519MLKEM768 | NamedGroup::secp256r1MLKEM768 => {
                Self::Hybrid(group.as_str().unwrap_or("unknown").to_owned())
            }
            NamedGroup::MLKEM512 | NamedGroup::MLKEM768 | NamedGroup::MLKEM1024 => {
                Self::Pure(group.as_str().unwrap_or("unknown").to_owned())
            }
            _ => Self::Classical,
        }
    }

    fn from_signature_scheme(scheme: &SignatureScheme) -> Self {
        match scheme {
            SignatureScheme::ML_DSA_44
            | SignatureScheme::ML_DSA_65
            | SignatureScheme::ML_DSA_87 => {
                Self::Pure(scheme.as_str().unwrap_or("unknown").to_owned())
            }
            _ => Self::Classical,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PqcDiagnostic {
    signature_scheme: PqcScheme,
    kex_scheme: PqcScheme,
}

impl PqcDiagnostic {
    pub fn is_anssi_pqc_compliant(&self) -> bool {
        match (&self.signature_scheme, &self.kex_scheme) {
            (PqcScheme::Hybrid(_), PqcScheme::Hybrid(_)) => true,
            _ => false,
        }
    }

    pub fn is_reasonably_pqc(&self) -> bool {
        matches!(self.kex_scheme, PqcScheme::Hybrid(_))
    }
}

#[derive(Debug, Clone)]
pub struct TlsInfo {
    pub version: TlsVersion,
    pub alpn: Option<Vec<HttpVersion>>,
    pub server_name_indication: Option<String>,
    pub pqc_coverage: PqcDiagnostic,
}
