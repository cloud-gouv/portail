/// General protocol detection algorithms.
/// Used for the outer tunnel and inner tunnel analysis.
pub mod tls;

use tokio::io::AsyncBufReadExt;
use tracing::debug;

use crate::proxy::context::InboundStream;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const ALPN_H2: &[u8] = b"h2";
pub const ALPN_HTTP1_1: &[u8] = b"http/1.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
    Http2_0,
    Http3_0,
}

#[derive(Debug, Clone)]
pub enum DetectedProtocol {
    Socks5,
    PlaintextHttp(HttpVersion),
    Ssh,
    Tls(tls::TlsInfo),
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum DetectionError {
    MoreDataRequired(Option<usize>),
    Inconclusive,
}

/// Given the buffer, this will try to recognize the protocol.
/// If it starts to recognize a protocol but do not have enough data, it will return a detection
/// error with "more data required".
/// If it cannot recognize the protocol, it will return an error "inconclusive".
pub fn classify_wire_protocol(buffer: &[u8]) -> Result<DetectedProtocol, DetectionError> {
    if buffer.is_empty() {
        return Err(DetectionError::MoreDataRequired(Some(1)));
    }

    if buffer[0] == 0x05 {
        return Ok(DetectedProtocol::Socks5);
    }

    if buffer.starts_with(&[0x16, 0x03]) {
        match tls::parse_tls_client_hello(buffer) {
            Ok(proto) => return Ok(proto),
            // A Client Hello can be as big as 300 bytes.
            Err(DetectionError::MoreDataRequired(n)) => {
                return Err(DetectionError::MoreDataRequired(n))
            }
            // Continue.
            Err(_) => {}
        }
    }

    if buffer.starts_with(b"SSH-") {
        return Ok(DetectedProtocol::Ssh);
    }

    classify_http_from_bytes(&buffer[..24.min(buffer.len())])
}

/// We use a different approach than `hyper-util` because we have access to the TLS session. We therefore use the following order to detect the protocol:
/// 1. If TLS, check ALPN
/// 2. check socks5 (first byte)
/// 3. check for H2_PREFACE (24 bytes)
/// 4. check for HTTP1 (first byte)
///
/// Refs:
/// - https://github.com/hyperium/hyper-util/blob/master/src/server/conn/auto/mod.rs
///
pub async fn detect_protocol(
    mut socket: InboundStream,
) -> Result<(DetectedProtocol, InboundStream), std::io::Error> {
    match &mut socket {
        InboundStream::TcpStream(stream) => {
            // We will take a reasonably large buffer.
            // FIXME: ensure this is big enough for PQC ClientHellos.
            // X25519MLKEM768 * 2 ~ 3200 bytes approx. ?
            let mut buf = [0u8; 4096];
            let n = stream.peek(&mut buf).await?;

            match classify_wire_protocol(&buf[..n]) {
                Ok(protocol) => return Ok((protocol, socket)),
                err @ Err(DetectionError::Inconclusive)
                | err @ Err(DetectionError::MoreDataRequired(_)) => {
                    debug!(buffer = ?buf, err = ?err, "Detection was inconclusive on a TCP stream which is surprising; unknown protocol in the tunnel");
                    Ok((DetectedProtocol::Unknown, socket))
                }
            }
        }

        InboundStream::TlsStream(tls) => {
            if let tokio_rustls::TlsStream::Server(server_stream) = tls {
                let (_io, session) = server_stream.get_ref();

                return Ok((tls::from_tls_session(session), socket));
            }

            loop {
                // NOTE: we do not consume here on purpose because we are peeking (.fill_buf() does not consume).
                let buf = tls.fill_buf().await?;

                // This is EOF.
                if buf.is_empty() {
                    return Ok((DetectedProtocol::Unknown, socket));
                }

                match classify_wire_protocol(buf) {
                    Ok(protocol) => return Ok((protocol, socket)),
                    Err(DetectionError::Inconclusive) => {
                        debug!(buffer = ?buf, "Detection was inconclusive on a TLS stream, continuing to peek until EOF");
                        continue;
                    }
                    Err(DetectionError::MoreDataRequired(n)) => {
                        debug!(buffer = ?buf, n = ?n, "Detection require more data on a TLS stream, continuing to peek until EOF");
                        continue;
                    }
                }
            }
        }
    }
}

fn classify_http_from_bytes(buffer: &[u8]) -> Result<DetectedProtocol, DetectionError> {
    if buffer.len() < 24 {
        // We need 24 bytes minimum to know if a stream is H2 or not.
        return Err(DetectionError::MoreDataRequired(Some(24 - buffer.len())));
    }

    if buffer.starts_with(H2_PREFACE) {
        Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http2_0))
    // FIXME: HTTP can contain arbitrary verbs.
    } else if matches!(buffer[0], b'C' | b'G' | b'P' | b'D' | b'H' | b'Q') {
        // FIXME: we assume H1.1 because this is the year of 2026.
        Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
    } else {
        Err(DetectionError::Inconclusive)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn test_classify_wire_protocol_empty_buffer() {
        let buffer = [];
        let result = classify_wire_protocol(&buffer);
        assert!(matches!(
            result,
            Err(DetectionError::MoreDataRequired(Some(1)))
        ));
    }

    #[test]
    fn test_classify_wire_protocol_socks5() {
        let buffer = [0x05, 0x01, 0x00];
        let result = classify_wire_protocol(&buffer);
        assert!(matches!(result, Ok(DetectedProtocol::Socks5)));
    }

    #[test]
    fn test_classify_wire_protocol_socks5_with_noise() {
        // SOCKS5 marker with additional data
        let buffer = [0x05, 0xFF, 0xFE, 0xFD, 0x01, 0x02, 0x03];
        let result = classify_wire_protocol(&buffer);
        assert!(matches!(result, Ok(DetectedProtocol::Socks5)));
    }

    #[test]
    fn test_classify_wire_protocol_tls_client_hello_incomplete() {
        // Incomplete TLS ClientHello
        let buffer = [0x16, 0x03, 0x03, 0x00];
        let result = classify_wire_protocol(&buffer);
        assert!(matches!(result, Err(DetectionError::MoreDataRequired(_))));
    }

    #[test]
    fn test_classify_wire_protocol_tls_client_hello_invalid_version() {
        // TLS handshake with invalid version
        let buffer = [0x16, 0x02, 0x03];
        let result = classify_wire_protocol(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_wire_protocol_ssh() {
        let buffer = b"SSH-2.0-OpenSSH_9.0\r\n";
        let result = classify_wire_protocol(buffer);
        assert!(matches!(result, Ok(DetectedProtocol::Ssh)));
    }

    #[test]
    fn test_classify_wire_protocol_ssh_partial() {
        let buffer = b"SSH-";
        let result = classify_wire_protocol(buffer);
        assert!(matches!(result, Ok(DetectedProtocol::Ssh)));
    }

    #[test]
    fn test_classify_wire_protocol_http2_preface() {
        let buffer = H2_PREFACE;
        let result = classify_wire_protocol(buffer);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http2_0))
        ));
    }

    #[test]
    fn test_classify_wire_protocol_http2_preface_with_extra() {
        let mut buffer = H2_PREFACE.to_vec();
        buffer.extend_from_slice(b"\x00\x00\x00\x04\x00\x00\x00\x00");
        let result = classify_wire_protocol(&buffer);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http2_0))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_get() {
        let buffer = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_post() {
        let buffer = b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_put() {
        let buffer = b"PUT /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_delete() {
        let buffer = b"DELETE /resource HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_head() {
        let buffer = b"QUERY / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(
            result,
            Ok(DetectedProtocol::PlaintextHttp(HttpVersion::Http1_1))
        ));
    }

    #[test]
    fn test_classify_http_from_bytes_http1_inconclusive_too_short() {
        let buffer = b"GET /";
        let result = classify_http_from_bytes(buffer);
        assert!(matches!(
            result,
            Err(DetectionError::MoreDataRequired(Some(n))) if n == 19 // 24 - 5
        ));
    }
    #[test]
    fn test_classify_http_from_bytes_http1_lowercase_method() {
        let buffer = b"get / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = classify_http_from_bytes(&buffer[..24]);
        assert!(matches!(result, Err(DetectionError::Inconclusive)));
    }

    #[test]
    fn test_classify_wire_protocol_garbage_data() {
        let buffer = b"\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8";
        let result = classify_wire_protocol(buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_wire_protocol_http2_preface_malformed() {
        let mut buffer = H2_PREFACE.to_vec();
        buffer[0] = 0xFF; // corrupt the first character otherwise this will get classify as
                          // HTTP1.1.
        buffer[5] = 0xFF; // corrupt the preface
        let result = classify_wire_protocol(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_wire_protocol_tls_with_socks5_byte_at_start() {
        // Starts with SOCKS5 marker but also looks like TLS
        let mut buffer = vec![0x05];
        buffer.extend_from_slice(&[0x16, 0x03, 0x03]);
        let result = classify_wire_protocol(&buffer);
        // Should detect as SOCKS5 first
        assert!(matches!(result, Ok(DetectedProtocol::Socks5)));
    }

    #[test]
    fn test_classify_wire_protocol_tls_client_hello_missing_cipher_suites() {
        // Minimal ClientHello with invalid cipher suite structure
        let mut buffer = vec![0x16, 0x03, 0x03];
        buffer.extend_from_slice(&[0x00, 0x00, 0x00]);
        buffer.extend_from_slice(&[0x00; 32]); // random
        buffer.push(0x00); // session ID
        buffer.extend_from_slice(&[0x00, 0x01]); // cipher suites length (odd)
        buffer.extend_from_slice(&[0x00]); // incomplete cipher suite
        let result = classify_wire_protocol(&buffer);
        // Should fail gracefully
        assert!(result.is_err());
    }

    #[test]
    fn test_classify_wire_protocol_tls_client_hello() {
        use std::sync::Arc;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::TlsConnector;

        let config = ClientConfig::builder()
            .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
            .with_no_client_auth();

        let config = Arc::new(config);
        let connector = TlsConnector::from(config);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client_hello = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = Vec::new();
                let mut buf = [0u8; 4096];

                // Read the ClientHello
                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            buffer.extend_from_slice(&buf[..n]);
                            // Check if we have a complete ClientHello
                            if buffer.len() >= 5 {
                                let record_len =
                                    u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                                if buffer.len() >= 5 + record_len {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                buffer
            });

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();

            let domain =
                tokio_rustls::rustls::pki_types::ServerName::try_from("example.com").unwrap();
            let _ = connector.connect(domain, stream).await;

            handle.await.unwrap()
        });

        let result = classify_wire_protocol(&client_hello);
        assert!(matches!(result, Ok(DetectedProtocol::Tls(_))));
    }

    #[test]
    fn test_classify_wire_protocol_tls_client_hello_with_alpn() {
        use std::sync::Arc;
        use tokio_rustls::rustls::ClientConfig;
        use tokio_rustls::TlsConnector;

        // Create a TLS config with ALPN
        let mut config = ClientConfig::builder()
            .with_root_certificates(tokio_rustls::rustls::RootCertStore::empty())
            .with_no_client_auth();

        // Set ALPN protocols
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let config = Arc::new(config);
        let connector = TlsConnector::from(config);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let client_hello = runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let handle = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = Vec::new();
                let mut buf = [0u8; 4096];

                loop {
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(100),
                        stream.read(&mut buf),
                    )
                    .await
                    {
                        Ok(Ok(n)) if n > 0 => {
                            buffer.extend_from_slice(&buf[..n]);
                            if buffer.len() >= 5 {
                                let record_len =
                                    u16::from_be_bytes([buffer[3], buffer[4]]) as usize;
                                if buffer.len() >= 5 + record_len {
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
                buffer
            });

            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let domain =
                tokio_rustls::rustls::pki_types::ServerName::try_from("example.com").unwrap();
            let _ = connector.connect(domain, stream).await;

            handle.await.unwrap()
        });

        let result = classify_wire_protocol(&client_hello);
        if let Ok(DetectedProtocol::Tls(tls_info)) = result {
            let alpn = tls_info.alpn.unwrap();
            // Verify ALPN is detected
            assert!(alpn.contains(&HttpVersion::Http2_0));
            assert!(alpn.contains(&HttpVersion::Http1_1));
        } else {
            panic!("Expected TLS detected");
        }
    }
}
