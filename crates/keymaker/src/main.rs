use tokio::net::TcpListener;
use tracing::{error, info};

#[global_allocator]
static ALLOC: zalloc::ZeroizingAlloc<std::alloc::System> =
    zalloc::ZeroizingAlloc(std::alloc::System);

#[tracing::instrument]
fn main() {
    if let Err(e) = run_server() {
        error!("error when running server: {e}");
        let mut source = e.source();
        while let Some(new_source) = source {
            error!("- caused by: {new_source}");
            source = new_source.source();
        }
    }
}

#[tracing::instrument]
#[tokio::main]
async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let (app, _state) = keymaker::app();

    let listen_addr =
        std::env::var("KEYMAKER_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".into());
    info!(%listen_addr, "binding listener");
    let listener = TcpListener::bind(&listen_addr).await?;

    info!("serving keymaker server");
    axum::serve(listener, app).await?;

    Ok(())
}
