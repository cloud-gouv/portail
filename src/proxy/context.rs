use std::net::SocketAddr;

pub enum InboundStream {
    TcpStream(tokio::net::TcpStream),
    TlsStream(tokio_rustls::TlsStream<tokio::net::TcpStream>),
}

enum ProxyProtocol {
    Socks5,
    Http1,
    Http2,
    Http3
}

pub struct TargetContext {
    pub initial_target: String,
    pub resolved_target: Option<String>,
}

pub struct RequestContext {
    pub client_address: SocketAddr,
    pub acl_eval_ctx: crate::acl::EvalContext
}

impl RequestContext {
    pub fn new(client_address: SocketAddr) -> Self {
        Self {
            client_address,
            acl_eval_ctx: crate::acl::EvalContext::new(),
        }
    }
}
