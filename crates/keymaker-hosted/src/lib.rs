//! Test surface for the keymaker-hosted server.
pub mod middleware;
pub mod routes;

use axum::{Router, routing};
use tower_http::limit::RequestBodyLimitLayer;

/// Max request body. A keyring of OpenPGP certs is small; cap to bound abuse.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

pub fn app() -> Router {
    Router::new()
        .route("/health", routing::get(routes::health))
        .route("/generate_quorum", routing::post(routes::generate_quorum))
        .layer(axum::middleware::from_fn(
            middleware::error_handling::error_logger_middleware,
        ))
        .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
        .layer(tower_http::trace::TraceLayer::new_for_http())
}
