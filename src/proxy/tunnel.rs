//! Shared tunnel pass-through seam for HTTP CONNECT and SOCKS5.

use std::{io, net::SocketAddr};

use tokio::io::{AsyncRead, AsyncWrite};
use tracing::info;
use uuid::Uuid;

use crate::proxy::{context::ClientTransport, stream::PrefixedStream, target::TargetAuthority};

const PEEK_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TunnelProtocol {
    Http,
    Socks5,
}

impl TunnelProtocol {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TunnelContext {
    pub trace_id: Uuid,
    pub client_address: SocketAddr,
    pub target: TargetAuthority,
    pub transport: ClientTransport,
    pub protocol: TunnelProtocol,
}

impl TunnelContext {
    pub(crate) fn new(
        trace_id: Uuid,
        client_address: SocketAddr,
        target: TargetAuthority,
        transport: ClientTransport,
        protocol: TunnelProtocol,
    ) -> Self {
        Self {
            trace_id,
            client_address,
            target,
            transport,
            protocol,
        }
    }
}

#[tracing::instrument(skip_all, fields(
    trace_id = %ctx.trace_id,
    client_address = %ctx.client_address,
    tunnel_protocol = ctx.protocol.as_str(),
    tunnel_transport = ctx.transport.as_str(),
    tunnel_host = ctx.target.host.as_str(),
    tunnel_port = ctx.target.port,
))]
pub(crate) async fn serve_passthrough<C, O>(
    ctx: &TunnelContext,
    client: C,
    mut origin: O,
) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let mut client = PrefixedStream::with_limit(client, PEEK_LIMIT);
    let (n_bytes_sent, n_bytes_recv) =
        tokio::io::copy_bidirectional(&mut client, &mut origin).await?;

    info!(
        subsystem = "proxy_access",
        n_bytes_sent = %n_bytes_sent,
        n_bytes_recv = %n_bytes_recv,
        "Tunnel finished"
    );

    Ok(())
}
