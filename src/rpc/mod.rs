use crate::{config::Settings, rpc::fr_gouv_portail_control::VarlinkInterface};
use std::sync::Arc;
use tokio::net::UnixListener;
use varlink::{
    sansio::Server,
    server_async::{handle_connection, AsyncStream},
    AsyncConnectionHandler, VarlinkService,
};

mod fr_gouv_portail_control;

struct Control;

impl VarlinkInterface for Control {
    fn ping(
        &self,
        call: &mut dyn fr_gouv_portail_control::Call_Ping,
        r#ping: String,
    ) -> varlink::Result<()> {
        return call.reply(ping);
    }
}

/// Spawn a Varlink server to control the proxy server.
pub async fn start(settings: Arc<Settings>, listener: UnixListener) -> anyhow::Result<()> {
    let control_interface = Box::new(fr_gouv_portail_control::new(Box::new(Control)));

    let svc = Arc::new(VarlinkService::new(
        "fr.gouv.dinum",
        "portail",
        "0.1.0",
        "https://github.com/cloud-gouv/portail",
        vec![control_interface],
    ));

    let listener = varlink::server_async::AsyncListener::UNIX(listener);
    while let Ok(stream) = listener.accept().await {
        handle_connection(stream, svc.clone()).await?;
    }

    Ok(())
}
