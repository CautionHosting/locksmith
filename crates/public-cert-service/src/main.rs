use std::sync::Arc;

use public_cert_service::{AppState, router};
use tokio::net::TcpListener;
use tracing::{error, info};

#[global_allocator]
static ALLOC: zalloc::ZeroizingAlloc<std::alloc::System> =
    zalloc::ZeroizingAlloc(std::alloc::System);

fn main() {
    if let Err(error) = run_server() {
        error!("error when running public certificate service: {error}");
        let mut source = error.source();
        while let Some(new_source) = source {
            error!("- caused by: {new_source}");
            source = new_source.source();
        }
    }
}

#[tokio::main]
async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let listen_addr =
        std::env::var("PUBLIC_CERT_SERVICE_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    info!(%listen_addr, "binding public certificate service listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    let app = router(Arc::new(AppState::new()));
    info!("serving public certificate service");
    axum::serve(listener, app).await?;

    Ok(())
}
