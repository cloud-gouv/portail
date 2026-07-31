use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use prometheus::{register_int_gauge_vec, Encoder, IntGaugeVec, TextEncoder};
use tokio::{net::TcpListener, sync::RwLock};

use crate::{config::Settings, state::State};

use hyper::{body::Incoming, service::service_fn, Request, Response};
use lazy_static::lazy_static;

lazy_static! {
    static ref PORTAIL_META: IntGaugeVec = register_int_gauge_vec!(
        "portail_metadata",
        "Metadata about deployed Portail such as version",
        &["version"]
    )
    .unwrap();
}

async fn handle_request(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        (&hyper::Method::GET, "/metrics") => {
            let mut buffer = Vec::new();
            TextEncoder::new()
                .encode(&prometheus::default_registry().gather(), &mut buffer)
                .unwrap();
            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "text/plain")
                .body(buffer.into())
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(404)
            .body("Not Found".into())
            .unwrap()),
    }
}

pub async fn serve(
    _settings: Arc<Settings>,
    _state: Arc<RwLock<State>>,
    listener: TcpListener,
) -> anyhow::Result<()> {
    PORTAIL_META
        .with_label_values(&[env!("CARGO_PKG_VERSION")])
        .set(1);
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(async move {
            let http = hyper::server::conn::http1::Builder::new();
            let conn = http.serve_connection(TokioIo::new(stream), service_fn(handle_request));
            if let Err(e) = conn.await {
                tracing::error!("HTTP error: {}", e);
            }
        });
    }

    Ok(())
}
