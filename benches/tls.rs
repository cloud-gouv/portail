use std::{
    collections::HashMap,
    future::poll_fn,
    sync::Arc,
    time::{Duration, Instant},
};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use futures::future::join_all;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use portail::{acl::ACLRules, proxy::client_tls::connect_using_tls_auth, state};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use tokio::{io::DuplexStream, sync::RwLock};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
};

const DUPLEX_BUF: usize = 64 * 1024;
const REQUEST_COUNTS: &[usize] = &[1, 5, 20];
const ROOT_COUNTS: &[usize] = &[1, 10, 100];

#[derive(Clone, Copy)]
enum Protocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy)]
enum BenchMode {
    Sequential,
    Multiplexed,
}

enum Sender {
    Http1(hyper::client::conn::http1::SendRequest<Empty<Bytes>>),
    Http2(hyper::client::conn::http2::SendRequest<Empty<Bytes>>),
}

fn empty_acl() -> ACLRules {
    ACLRules::default()
}

struct Context {
    state: Arc<RwLock<state::State>>,
    acceptor: TlsAcceptor,
}

fn setup_context(root_count: usize) -> Context {
    let mut roots = RootCertStore::empty();

    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut ca_params = CertificateParams::new(vec!["CA 0".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

    let cert = ca_params.self_signed(&ca_key).unwrap();

    roots
        .add(CertificateDer::from(cert.der().to_vec()))
        .unwrap();

    for i in 1..root_count {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

        let mut params = CertificateParams::new(vec![format!("CA {i}")]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let cert = params.self_signed(&key).unwrap();

        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();
    }

    let issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

    let mut server_params = CertificateParams::new(vec![]).unwrap();
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    server_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));

    let server_cert = server_params.signed_by(&server_key, &issuer).unwrap();

    let mut server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .unwrap();

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let state = state::State {
        default_backend: None,
        acl_rules: empty_acl(),
        root_store: Some(Arc::new(roots)),
        server_certificates: None,
        client_cert_resolver: None,
        backends: HashMap::new(),
    };

    Context {
        state: Arc::new(RwLock::new(state)),
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    }
}

async fn serve(acceptor: TlsAcceptor, io: DuplexStream) {
    let tls = match acceptor.accept(io).await {
        Ok(v) => v,
        Err(_) => return,
    };

    let alpn = tls.get_ref().1.alpn_protocol().map(|x| x.to_vec());

    let service = hyper::service::service_fn(|_| async {
        Ok::<_, hyper::Error>(hyper::Response::new(Empty::<Bytes>::new()))
    });

    let io = TokioIo::new(tls);

    match alpn.as_deref() {
        Some(b"h2") => {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await;
        }
        _ => {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await;
        }
    }
}

struct RequestTemplate {
    uri: http::Uri,
    host: http::HeaderValue,
}

impl RequestTemplate {
    fn new() -> Self {
        Self {
            uri: "/".parse().unwrap(),
            host: "localhost".parse().unwrap(),
        }
    }

    fn build(&self) -> hyper::Request<Empty<Bytes>> {
        hyper::Request::builder()
            .uri(self.uri.clone())
            .header("host", self.host.clone())
            .body(Empty::new())
            .unwrap()
    }
}

struct SessionKeeper {
    driver: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for SessionKeeper {
    fn drop(&mut self) {
        self.driver.abort();
        self.server.abort();
    }
}

struct Session {
    sender: Sender,
    _keeper: SessionKeeper,
}

impl Session {
    async fn new(
        protocol: Protocol,
        acceptor: TlsAcceptor,
        state: Arc<RwLock<state::State>>,
    ) -> Self {
        let (client, server) = tokio::io::duplex(DUPLEX_BUF);
        let server_task = tokio::spawn(serve(acceptor, server));

        let alpn = match protocol {
            Protocol::Http1 => vec![b"http/1.1".to_vec()],
            Protocol::Http2 => vec![b"h2".to_vec()],
        };

        let tls = connect_using_tls_auth(
            client,
            ServerName::try_from("localhost").unwrap(),
            state,
            alpn,
        )
        .await
        .unwrap();

        let io = TokioIo::new(tls);

        let (sender, driver) = match protocol {
            Protocol::Http1 => {
                let (s, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
                let d = tokio::spawn(async move {
                    let _ = conn.await;
                });
                (Sender::Http1(s), d)
            }
            Protocol::Http2 => {
                let (s, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .unwrap();
                let d = tokio::spawn(async move {
                    let _ = conn.await;
                });
                (Sender::Http2(s), d)
            }
        };

        Self {
            sender,
            _keeper: SessionKeeper {
                driver,
                server: server_task,
            },
        }
    }

    async fn execute(&mut self, mode: BenchMode, count: usize, template: &RequestTemplate) {
        match mode {
            BenchMode::Sequential => {
                for _ in 0..count {
                    let req = template.build();
                    match &mut self.sender {
                        Sender::Http1(s) => {
                            poll_fn(|cx| s.poll_ready(cx)).await.unwrap();
                            let resp = s.send_request(req).await.unwrap();
                            resp.collect().await.unwrap();
                        }
                        Sender::Http2(s) => {
                            poll_fn(|cx| s.poll_ready(cx)).await.unwrap();
                            let resp = s.send_request(req).await.unwrap();
                            resp.collect().await.unwrap();
                        }
                    }
                }
            }
            BenchMode::Multiplexed => {
                if let Sender::Http2(s) = &self.sender {
                    let futs = (0..count).map(|_| {
                        let mut sender = s.clone();
                        let req = template.build();
                        async move {
                            poll_fn(|cx| sender.poll_ready(cx)).await.unwrap();
                            let resp = sender.send_request(req).await.unwrap();
                            resp.collect().await.unwrap();
                        }
                    });
                    join_all(futs).await;
                }
            }
        }
    }
}

fn run_bench_group(
    c: &mut Criterion,
    rt: &tokio::runtime::Runtime,
    group_name: &str,
    protocol: Protocol,
    mode: BenchMode,
) {
    let mut group = c.benchmark_group(group_name);
    group.warm_up_time(Duration::from_secs(1));

    for &count in REQUEST_COUNTS {
        group.throughput(Throughput::Elements(count as u64));

        let ctx = setup_context(ROOT_COUNTS[1]);
        let template = RequestTemplate::new();

        group.bench_with_input(BenchmarkId::from_parameter(count), &count, |b, &count| {
            let mut session = rt.block_on(Session::new(
                protocol,
                ctx.acceptor.clone(),
                ctx.state.clone(),
            ));
            b.iter_custom(|iters| {
                let start = Instant::now();
                rt.block_on(async {
                    for _ in 0..iters {
                        session.execute(mode, count, &template).await;
                    }
                });
                start.elapsed()
            });
        });
    }
    group.finish();
}

fn bench_proxy(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    run_bench_group(
        c,
        &rt,
        "http1_keepalive",
        Protocol::Http1,
        BenchMode::Sequential,
    );
    run_bench_group(
        c,
        &rt,
        "http2_sequential",
        Protocol::Http2,
        BenchMode::Sequential,
    );
    run_bench_group(
        c,
        &rt,
        "http2_multiplexed",
        Protocol::Http2,
        BenchMode::Multiplexed,
    );
}

criterion_group!(benches, bench_proxy);
criterion_main!(benches);
