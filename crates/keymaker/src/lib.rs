pub mod routes;

use axum::{Router, routing};
use tokio::sync::Semaphore;
use std::sync::Arc;

pub struct AppState {
    pub reboot_permit: Semaphore,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            reboot_permit: Semaphore::new(1),
        }
    }
}

/// Returns the router and the shared state (state is also wired into the router).
pub fn app() -> (Router, Arc<AppState>) {
    let state = Arc::new(AppState::new());
    let router = Router::new()
        .route("/health", routing::get(routes::health::health))
        .route(
            "/generate_quorum",
            routing::post(routes::generate_quorum::generate_quorum),
        )
        .layer(axum::middleware::from_fn(
            keymaker_core::http::error_logger_middleware,
        ))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(Arc::clone(&state));
    (router, state)
}
