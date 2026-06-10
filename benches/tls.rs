use std::sync::Arc;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use http_body_util::{BodyExt, Empty, Full};
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

fn empty_acl() -> ACLRules {
    ACLRules::default()
}

struct Context {
    state: Arc<RwLock<state::State>>,
    acceptor: TlsAcceptor,
}

fn setup_context(root_count: usize) -> Context {
    let mut roots = RootCertStore::empty();

    let mut ca_key: Option<KeyPair> = None;
    let mut ca_params: Option<CertificateParams> = None;

    for i in 0..root_count {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();

        let mut params = CertificateParams::new(vec![format!("CA {i}")]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let cert = params.self_signed(&key).unwrap();

        roots
            .add(CertificateDer::from(cert.der().to_vec()))
            .unwrap();

        if i == 0 {
            ca_key = Some(key);
            ca_params = Some(params);
        }
    }

    let ca_key = ca_key.expect("missing CA key");
    let ca_params = ca_params.expect("missing CA params");
    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
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
    };

    Context {
        state: Arc::new(RwLock::new(state)),
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
    }
}

async fn serve(acceptor: TlsAcceptor, io: DuplexStream) {
    let tls = match acceptor.accept(io).await {
        Ok(tls) => tls,
        Err(_) => return,
    };

    let alpn = tls.get_ref().1.alpn_protocol().map(|v| v.to_vec());
    let service = hyper::service::service_fn(|_| async {
        Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from_static(b"OK"))))
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

async fn http1_session(acceptor: TlsAcceptor, state: Arc<RwLock<state::State>>, requests: usize) {
    let (client, server) = tokio::io::duplex(1024 * 1024);

    let server_task = tokio::spawn(serve(acceptor, server));

    let tls = connect_using_tls_auth(
        client,
        ServerName::try_from("localhost").unwrap(),
        state,
        vec![b"http/1.1".to_vec()],
    )
    .await
    .unwrap();

    let io = TokioIo::new(tls);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    for _ in 0..requests {
        let req = hyper::Request::builder()
            .uri("/")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();

        let response = sender.send_request(req).await.unwrap();

        response.collect().await.unwrap();
    }

    drop(sender);

    driver.abort();
    server_task.abort();
}

async fn http2_session(
    acceptor: TlsAcceptor,
    state: Arc<RwLock<state::State>>,
    concurrency: usize,
) {
    let (client, server) = tokio::io::duplex(1024 * 1024);

    let server_task = tokio::spawn(serve(acceptor, server));

    let tls = connect_using_tls_auth(
        client,
        ServerName::try_from("localhost").unwrap(),
        state,
        vec![b"h2".to_vec()],
    )
    .await
    .unwrap();

    let io = TokioIo::new(tls);

    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .unwrap();

    let driver = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut tasks = Vec::with_capacity(concurrency);

    for _ in 0..concurrency {
        let mut sender = sender.clone();

        tasks.push(tokio::spawn(async move {
            let req = hyper::Request::builder()
                .uri("/")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap();

            let response = sender.send_request(req).await.unwrap();

            response.collect().await.unwrap();
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    drop(sender);

    driver.abort();
    server_task.abort();
}

fn bench_proxy(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let ctx = setup_context(10);

    let mut group = c.benchmark_group("proxy_http1");

    for requests in [1usize, 5, 20] {
        group.throughput(Throughput::Elements(requests as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(requests),
            &requests,
            |b, &requests| {
                let acceptor = ctx.acceptor.clone();

                let state = ctx.state.clone();

                b.to_async(&rt)
                    .iter(|| http1_session(acceptor.clone(), state.clone(), requests));
            },
        );
    }

    group.finish();

    let mut group = c.benchmark_group("proxy_http2");

    for concurrency in [1usize, 8, 32] {
        group.throughput(Throughput::Elements(concurrency as u64));

        group.bench_with_input(
            BenchmarkId::from_parameter(concurrency),
            &concurrency,
            |b, &concurrency| {
                let acceptor = ctx.acceptor.clone();

                let state = ctx.state.clone();

                b.to_async(&rt)
                    .iter(|| http2_session(acceptor.clone(), state.clone(), concurrency));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_proxy);
criterion_main!(benches);
