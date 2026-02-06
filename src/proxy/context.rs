use std::net::SocketAddr;

pub enum InboundStream {
    TcpStream(tokio::net::TcpStream),
    TlsStream(tokio_rustls::TlsStream<tokio::net::TcpStream>),
}

enum ProxyProtocol {
    Socks5,
    Http1,
    Http2,
    Http3,
}

pub struct TargetContext {
    pub initial_target: String,
    pub resolved_target: Option<String>,
}

#[derive(Clone)]
pub struct RequestContext<'s> {
    pub client_address: SocketAddr,
    pub acl_ctx: crate::acl::EvaluationContext<'s>,
}

impl<'s> RequestContext<'s> {
    pub fn new(client_address: SocketAddr) -> Self {
        Self {
            client_address,
            acl_ctx: crate::acl::EvaluationContext::empty(),
        }
    }
}
