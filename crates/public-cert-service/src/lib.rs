//! Public certificate derivation service foundations.
//!
//! This crate owns the service-side logic for deriving Caution-backed public
//! OpenPGP certificates from API-authorized organization and bundle IDs.  The
//! current implementation establishes the request validation, HTTP boundary,
//! deterministic Keyfork derivation path construction, and OpenPGP certificate
//! derivation used by v1 public certificate bundles.

pub mod derivation;
pub mod release;
pub mod routes;

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;

#[derive(Default)]
pub struct AppState {
    pub release: Option<Arc<locksmith::release::Authorizer>>,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route(
            "/v1/public-certificates",
            post(routes::derive_public_certificates),
        )
        .layer(DefaultBodyLimit::max(4096))
        .route(
            "/v1/releases/begin",
            post(release::begin).layer(DefaultBodyLimit::max(2 * 1024 * 1024)),
        )
        .route(
            "/v1/releases/prepare",
            post(release::prepare).layer(DefaultBodyLimit::max(32768)),
        )
        .route(
            "/v1/releases/complete",
            post(release::complete).layer(DefaultBodyLimit::max(16384)),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
