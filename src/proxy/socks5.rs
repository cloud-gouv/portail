use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use fast_socks5::{
    client::Socks5Stream, server::Socks5ServerProtocol, util::target_addr::TargetAddr, ReplyError,
    Socks5Command, SocksError,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::RwLock,
};
use tokio_rustls::{rustls::pki_types::ServerName, TlsStream};
use tracing::{debug, info, warn};

use crate::{
    config::{BackendSettings, Settings},
    proxy::context::{InitialRequestContext, TargetContext},
    state::State,
};

pub enum OutboundSock5Stream {
    Tls(Socks5Stream<TlsStream<TcpStream>>),
    Plain(Socks5Stream<TcpStream>),
}

pub async fn connect_to_backend(
    backend: &BackendSettings,
    final_address: &TargetAddr,
    state: Arc<RwLock<State>>, // TODO: better error type
) -> Result<OutboundSock5Stream, SocksError> {
    let config = fast_socks5::client::Config::default();
    let (target_addr, target_port) = final_address.clone().into_string_and_port();

    if backend.identity_aware {
        debug!("Backend is identity-aware, establishing a TLS connection to the backend first");
        // TODO: remove the panic
        let domain = ServerName::try_from(target_addr).unwrap();
        let target_socket = TcpStream::connect(backend.target_address).await?;
        let stream = crate::proxy::client_tls::connect_using_tls_auth(
            target_socket,
            domain,
            state.clone(),
            vec![],
        )
        .await?;

        Ok(OutboundSock5Stream::Tls(
            Socks5Stream::use_stream(stream, None, config).await?,
        ))
    } else {
        debug!(
            "Backend is not identity-aware, establishing a plain SOCKS5 connection to the backend"
        );
        Ok(OutboundSock5Stream::Plain(
            Socks5Stream::connect(backend.target_address, target_addr, target_port, config).await?,
        ))
    }
}

pub async fn route_to_backend<S: AsyncRead + Unpin + AsyncWrite>(
    outbound_stream: OutboundSock5Stream,
    protocol: Socks5ServerProtocol<S, fast_socks5::server::states::CommandRead>,
) -> Result<(), SocksError> {
    let inner = protocol
        .reply_success(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0))
        .await?;

    match outbound_stream {
        OutboundSock5Stream::Tls(s) => fast_socks5::server::transfer(inner, s).await,
        OutboundSock5Stream::Plain(s) => fast_socks5::server::transfer(inner, s).await,
    }

    Ok(())
}

pub async fn serve_socks5<'s, S: AsyncRead + Unpin + AsyncWrite>(
    opts: Arc<Settings>,
    state: Arc<RwLock<State>>,
    ctx: InitialRequestContext,
    socket: S,
) -> Result<(), SocksError> {
    let mut ctx = ctx.into_local();
    let should_resolve_dns: bool = state.read().await.default_backend.is_none();

    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await?
        .read_command()
        .await?;

    ctx.acl_ctx.insert(
        "proxy.protocol",
        crate::acl::ast::ConcreteOperand::String("socks5"),
    );

    let mut target_context = TargetContext {
        initial_target: target_addr.clone().into(),
        resolved_target: None,
    };
    let target_addr = if should_resolve_dns {
        target_addr.resolve_dns().await?
    } else {
        target_addr
    };

    let (host, port) = target_context.initial_target.clone().into_string_and_port();

    ctx.acl_ctx
        .insert("host", crate::acl::ast::ConcreteOperand::String(&host));
    ctx.acl_ctx.insert(
        "port",
        crate::acl::ast::ConcreteOperand::Number(port.into()),
    );

    let mut final_addr = target_addr.clone();

    target_context.resolved_target = if should_resolve_dns {
        Some(target_addr.into())
    } else {
        None
    };

    if cmd != Socks5Command::TCPConnect && cmd != Socks5Command::UDPAssociate {
        debug!("Unsupported SOCKS5 command received, terminating connection");
        proto.reply_error(&ReplyError::CommandNotSupported).await?;
        return Err(ReplyError::CommandNotSupported.into());
    }

    if cmd == Socks5Command::TCPConnect {
        ctx.acl_ctx.insert(
            "proxy.cmd",
            crate::acl::ast::ConcreteOperand::String("tcp_connect"),
        );
    }

    if cmd == Socks5Command::UDPAssociate {
        ctx.acl_ctx.insert(
            "proxy.cmd",
            crate::acl::ast::ConcreteOperand::String("udp_associate"),
        );
    }

    let mut backends: Vec<&BackendSettings> = Vec::with_capacity(1);
    // We evaluate first whether we are allowed then we evaluate routes.
    let acl = &state.read().await.acl_rules;
    let assessment = ctx.acl_ctx.evaluate_request(&acl.hir);
    if let Err(failure) = assessment {
        proto.reply_error(&ReplyError::GeneralFailure).await?;
        warn!(
            "Failed to evaluate a request: {} (Context: {:#?})",
            failure, ctx
        );
        return Ok(());
    }

    let assessment = assessment.unwrap();

    match assessment.action {
        // FIXME: render the deny template if there's one.
        crate::acl::Action::Deny(_explain_template) => {
            info!("Request to {0} is blocked", &target_context.initial_target);
            proto.reply_error(&ReplyError::ConnectionNotAllowed).await?;
            return Ok(());
        }
        crate::acl::Action::Redirect(target) => {
            info!(
                "Request to {} redirected to {}",
                &target_context.initial_target, target
            );
            final_addr = TargetAddr::Domain(
                target
                    .host()
                    .expect("BUG: Redirect target should be an FQDN")
                    .to_owned(),
                // FIXME: calculation of the default port should be better and take into account
                // the scheme.
                target.port_u16().unwrap_or(80),
            );
        }

        _ => {}
    }

    let recommended_routes = ctx.acl_ctx.evaluate_routes(&acl.hir);
    if let Err(failure) = recommended_routes {
        proto.reply_error(&ReplyError::GeneralFailure).await?;
        warn!(
            "Failed to evaluate routes for a request: {} (Context: {:#?})",
            failure, ctx
        );
        return Ok(());
    }

    let mut recommended_routes = recommended_routes.unwrap();

    if !recommended_routes.is_empty() {
        backends.append(&mut recommended_routes);
    }

    if backends.is_empty() {
        if let Some(ref backend_id) = state.read().await.default_backend {
            let backend = opts.backends.get(backend_id).expect(&format!(
                "BUG: default backend {backend_id} went away from settings"
            ));

            backends.push(backend);
        }
    }

    backends.reverse();

    // Either, we route to another backend or we do the SOCKS5 proxying ourselves.
    while let Some(backend) = backends.pop() {
        debug!(
            "Backend {} selected for routing the connection",
            &backend.target_address
        );

        match connect_to_backend(backend, &final_addr, state.clone()).await {
            Ok(stream) => {
                route_to_backend(stream, proto).await?;
                return Ok(());
            }

            Err(err) => {
                debug!(
                    "Backend {} failed to route the request: {err}, trying the next one",
                    &backend.target_address
                );
                continue;
            }
        }
    }

    // If we get there, this means that we did not have any backend at all.
    {
        debug!("No backend, terminating the connection ourself");
        match cmd {
            Socks5Command::TCPConnect => {
                fast_socks5::server::run_tcp_proxy(
                    proto,
                    &final_addr,
                    opts.request_timeout.to_std().unwrap(),
                    opts.tcp_nodelay,
                )
                .await?;
            }

            Socks5Command::UDPAssociate if opts.public_address.is_some() => {
                fast_socks5::server::run_udp_proxy(
                    proto,
                    &final_addr,
                    None,
                    opts.public_address.unwrap(),
                    None,
                )
                .await?;
            }

            _ => {
                proto.reply_error(&ReplyError::CommandNotSupported).await?;
                return Err(ReplyError::CommandNotSupported.into());
            }
        }
    }

    Ok(())
}
