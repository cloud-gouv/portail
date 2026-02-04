use tokio::io::AsyncBufReadExt;

use crate::proxy::context::InboundStream;

pub enum DetectedProtocol {
    Socks5,
    Http,
    Unknown,
}

pub async fn detect_protocol(
   mut socket: InboundStream
) -> Result<(DetectedProtocol, InboundStream), std::io::Error> {
    let mut buf = [0u8; 1];

    match socket {
        InboundStream::TcpStream(ref socket) => {
            socket.peek(&mut buf).await?;
        }

        InboundStream::TlsStream(ref mut socket) => {
            let new_buffer = socket.fill_buf().await?;
            buf[0] = new_buffer[0];
            // NOTE: we do not consume here on purpose because we are peeking.
        }
    };

    let proto = match buf[0] {
        0x05 => DetectedProtocol::Socks5,
        // FIXME: HTTP can contain arbitrary verbs.
        b'C' | b'G' | b'P' | b'D' | b'H' => DetectedProtocol::Http,
        _ => DetectedProtocol::Unknown,
    };

    Ok((proto, socket))
}

pub async fn detect_tls(
    stream: &tokio::net::TcpStream,
) -> std::io::Result<bool> {
    let mut buf = [0u8; 3];
    let n = stream.peek(&mut buf).await?;

    if n < 3 {
        return Ok(false);
    }

    Ok(buf[0] == 0x16 && buf[1] == 0x03)
}

