use tokio::io::AsyncBufReadExt;

use crate::proxy::context::InboundStream;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub enum DetectedProtocol {
    Socks5,
    Http1,
    Http2,
    Unknown,
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
            let mut buf = [0u8; 24];
            let n = stream.peek(&mut buf).await?;
            if n == 0 {
                return Ok((DetectedProtocol::Unknown, socket));
            }
            if buf[0] == 0x05 {
                return Ok((DetectedProtocol::Socks5, socket));
            }
            let proto = classify_http_from_bytes(buf);
            Ok((proto, socket))
        }

        InboundStream::TlsStream(tls) => {
            if let tokio_rustls::TlsStream::Server(server_stream) = tls {
                let (_io, session) = server_stream.get_ref();
                if let Some(alpn) = session.alpn_protocol() {
                    let alpn: &[u8] = alpn.as_ref();
                    if alpn == b"h2" {
                        return Ok((DetectedProtocol::Http2, socket));
                    }
                    if alpn == b"http/1.1" {
                        return Ok((DetectedProtocol::Http1, socket));
                    }
                }
            }

            // NOTE: we do not consume here on purpose because we are peeking (.fill_buf() does not consume).
            let buf = tls.fill_buf().await?;
            if buf.is_empty() {
                return Ok((DetectedProtocol::Unknown, socket));
            }
            if buf[0] == 0x05 {
                return Ok((DetectedProtocol::Socks5, socket));
            }
            let mut arr = [0u8; 24];
            let n = buf.len().min(24);
            arr[..n].copy_from_slice(&buf[..n]);
            let proto = classify_http_from_bytes(arr);
            Ok((proto, socket))
        }
    }
}

fn classify_http_from_bytes(buf: [u8; 24]) -> DetectedProtocol {
    if buf == *H2_PREFACE {
        DetectedProtocol::Http2
        // FIXME: HTTP can contain arbitrary verbs.
    } else if matches!(buf[0], b'C' | b'G' | b'P' | b'D' | b'H') {
        DetectedProtocol::Http1
    } else {
        DetectedProtocol::Unknown
    }
}

pub async fn detect_tls(stream: &tokio::net::TcpStream) -> std::io::Result<bool> {
    let mut buf = [0u8; 3];
    let n = stream.peek(&mut buf).await?;

    if n < 3 {
        return Ok(false);
    }

    Ok(buf[0] == 0x16 && buf[1] == 0x03)
}
