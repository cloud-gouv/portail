//! A read-ahead wrapper that lets callers inspect bytes before consuming them.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// A stream that can read ahead and replay the buffered bytes.
#[derive(Debug)]
pub struct PrefixedStream<IO> {
    inner: IO,
    prefix: BytesMut,
    limit: usize,
}

impl<IO> PrefixedStream<IO> {
    pub fn with_limit(inner: IO, limit: usize) -> Self {
        Self {
            inner,
            prefix: BytesMut::new(),
            limit,
        }
    }

    // Used by inner termination detection.
    #[allow(dead_code)]
    pub fn buffered(&self) -> &[u8] {
        &self.prefix
    }

    // Used by inner termination detection.
    #[allow(dead_code)]
    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl<IO: AsyncRead + Unpin> PrefixedStream<IO> {
    /// Read ahead until at least `target` bytes are buffered, EOF is reached,
    /// or the configured limit is hit. The bytes are not consumed.
    // Used by inner termination detection.
    #[allow(dead_code)]
    pub async fn fill(&mut self, target: usize) -> io::Result<()> {
        let target = target.min(self.limit);

        while self.prefix.len() < target {
            let remaining = self.limit - self.prefix.len();
            let mut buffer = [0u8; 4096];
            let want = remaining.min(buffer.len());

            let read = self.inner.read(&mut buffer[..want]).await?;
            if read == 0 {
                break;
            }

            self.prefix.extend_from_slice(&buffer[..read]);
        }

        Ok(())
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for PrefixedStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        if !this.prefix.is_empty() {
            let length = this.prefix.len().min(buf.remaining());
            buf.put_slice(&this.prefix[..length]);
            this.prefix.advance(length);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[tokio::test]
    async fn fill_reads_ahead_without_consuming() {
        let (mut peer, inner) = duplex(64);
        peer.write_all(b"hello world").await.unwrap();

        let mut stream = PrefixedStream::with_limit(inner, 64);
        stream.fill(5).await.unwrap();

        assert!(stream.buffered().starts_with(b"hello"));
    }

    #[tokio::test]
    async fn reads_replay_the_prefix_then_the_inner_stream() {
        let (mut peer, inner) = duplex(64);
        peer.write_all(b"hello world").await.unwrap();

        let mut stream = PrefixedStream::with_limit(inner, 64);
        stream.fill(5).await.unwrap();
        assert!(stream.buffered().starts_with(b"hello"));

        let mut output = [0u8; 11];
        stream.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"hello world");
    }

    #[tokio::test]
    async fn fill_stops_at_eof() {
        let (mut peer, inner) = duplex(64);
        peer.write_all(b"abc").await.unwrap();
        drop(peer);

        let mut stream = PrefixedStream::with_limit(inner, 64);
        stream.fill(10).await.unwrap();

        assert_eq!(stream.buffered(), b"abc");
    }

    #[tokio::test]
    async fn fill_stops_at_the_limit() {
        let (mut peer, inner) = duplex(64);
        peer.write_all(b"abcdefghij").await.unwrap();

        let mut stream = PrefixedStream::with_limit(inner, 4);
        stream.fill(10).await.unwrap();

        assert_eq!(stream.buffered(), b"abcd");
    }
}
