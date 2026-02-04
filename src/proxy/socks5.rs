use std::{net::{IpAddr, Ipv4Addr, SocketAddr}, sync::Arc};

use fast_socks5::{ReplyError, Socks5Command, SocksError, client::Socks5Stream, server::Socks5ServerProtocol, util::target_addr::TargetAddr};
use tokio::{io::{AsyncRead, AsyncWrite}, net::TcpStream, sync::RwLock};
use tokio_rustls::{TlsStream, rustls::pki_types::ServerName};
use tracing::{debug, info};

use crate::{config::{BackendSettings, Settings}, proxy::context::{RequestContext, TargetContext}, state::State};

pub enum OutboundSock5Stream {
    Tls(Socks5Stream<TlsStream<TcpStream>>),
    Plain(Socks5Stream<TcpStream>),
}

pub async fn connect_to_backend(
    backend: &BackendSettings,
    final_address: &TargetAddr,
    state: Arc<RwLock<State>>
    // TODO: better error type
) -> Result<OutboundSock5Stream, SocksError> {
    let config = fast_socks5::client::Config::default();
    let (target_addr, target_port) = final_address.clone().into_string_and_port();
    
    if backend.identity_aware {
        debug!("Backend is identity-aware, establishing a TLS connection to the backend first");
        // TODO: remove the panic
        let domain = ServerName::try_from(target_addr).unwrap();
        let target_socket = TcpStream::connect(backend.target_address).await?;
        let stream = crate::proxy::client_tls::connect_using_tls_auth(target_socket,
            domain,
            state.clone()
        ).await?;

        Ok(OutboundSock5Stream::Tls(Socks5Stream::use_stream(stream, None, config).await?))
    } else {
        debug!("Backend is not identity-aware, establishing a plain SOCKS5 connection to the backend");
        Ok(OutboundSock5Stream::Plain(Socks5Stream::connect(
            backend.target_address,
            target_addr,
            target_port,
            config,
        )
        .await?))
    }
}

pub async fn route_to_backend<S: AsyncRead + Unpin + AsyncWrite>(
    outbound_stream: OutboundSock5Stream,
    protocol: Socks5ServerProtocol<S, fast_socks5::server::states::CommandRead>
) -> Result<(), SocksError> {
    let inner = protocol
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    match outbound_stream {
        OutboundSock5Stream::Tls(s) => fast_socks5::server::transfer(inner, s).await,
        OutboundSock5Stream::Plain(s) => fast_socks5::server::transfer(inner, s).await
    }

    Ok(())
}

pub async fn serve_socks5<S: AsyncRead + Unpin + AsyncWrite>(
    opts: Arc<Settings>,
    state: Arc<RwLock<State>>,
    mut ctx: RequestContext,
    socket: S,
) -> Result<(), SocksError> {
    let should_resolve_dns: bool = state.read().await.default_backend.is_none();

    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket).await?.read_command().await?;

    // TODO: ctx.acl_eval_ctx.set("proto", "socks5");

    let mut target_context = TargetContext { initial_target: format!("{}", target_addr), resolved_target: None };
    let target_addr = if should_resolve_dns { target_addr.resolve_dns().await? } else { target_addr };
    
    target_context.resolved_target = if should_resolve_dns { Some(format!("{}", target_addr)) } else { None };

    let mut final_addr = target_addr.clone();

    if cmd != Socks5Command::TCPConnect && cmd != Socks5Command::UDPAssociate {
        debug!("Unsupported SOCKS5 command received, terminating connection");
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }

    if cmd == Socks5Command::TCPConnect {
        // TODO: ctx.acl_eval_ctx.set("socks5.cmd", "tcp_connect")
    }

    if cmd == Socks5Command::UDPAssociate {
        // TODO: ctx.acl_eval_ctx.set("socks5.cmd", "udp_associate")
    }

    let mut backends: Vec<&BackendSettings> = Vec::with_capacity(1);
    if let Some(rule) = crate::acl::evaluate(target_context.initial_target.as_str(), 
        &state.read().await.acl_rules, &mut ctx.acl_eval_ctx) {
        match rule.action {
            crate::acl::Action::Deny => {
                info!("Request to {0} is blocked", &target_context.initial_target);
                proto.reply_error(&ReplyError::ConnectionNotAllowed).await?;
                return Ok(());
            }
            crate::acl::Action::Redirect(target) => {
                info!("Request to {} redirected to {}", &target_context.initial_target, target);
                final_addr = target;
            }
            _ => {}
        }

        if let Some(recommended_backends) = rule.backends {
            let mut recommended_backends = recommended_backends.into_iter()
                .flat_map(|id| opts.backends.get(&id)).collect();
            backends.append(&mut recommended_backends);
        }
    }

    if backends.is_empty() {
        if let Some(ref backend_id) = state.read().await.default_backend {
            let backend = opts.backends.get(backend_id)
                .expect(&format!("BUG: default backend {backend_id} went away from settings"));

            backends.push(backend);
        }
    }

    backends.reverse();

    // Either, we route to another backend or we do the SOCKS5 proxying ourselves.
    while let Some(backend) = backends.pop() {
        debug!("Backend {} selected for routing the connection", &backend.target_address);

        match connect_to_backend(backend, &final_addr, state.clone()).await {
            Ok(stream) => {
                route_to_backend(stream, proto).await?;
                return Ok(());
            }

            Err(err) => {
                debug!("Backend {} failed to route the request: {err}, trying the next one", &backend.target_address);
                continue;
            }
        }
    }

    // If we get there, this means that we did not have any backend at all.
    {
        debug!("No backend, terminating the connection ourself");
        match cmd {
            Socks5Command::TCPConnect => {
                fast_socks5::server::run_tcp_proxy(proto, &final_addr, opts.request_timeout.to_std().unwrap(), opts.tcp_nodelay).await?;
            }

            Socks5Command::UDPAssociate if opts.public_address.is_some() => {
                fast_socks5::server::run_udp_proxy(proto, &final_addr, None, opts.public_address.unwrap(), None).await?;
            }

            _ => {
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                return Err(ReplyError::CommandNotSupported.into());
            }
        }
    }

    Ok(())
}
