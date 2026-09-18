//! Public certificate derivation service foundations.
//!
//! This crate owns the service-side logic for deriving Caution-backed public
//! OpenPGP certificates from API-authorized organization and bundle IDs.  The
//! current implementation establishes the request validation, HTTP boundary,
//! deterministic Keyfork derivation path construction, and OpenPGP certificate
//! derivation used by v1 public certificate bundles.

mod admission;
pub mod derivation;
pub mod release;
pub mod routes;
mod service;

use std::sync::Arc;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tower_http::trace::TraceLayer;

pub struct AppState {
    pub release: Option<Arc<locksmith::release::Authorizer>>,
    pub expected_ca: Option<sequoia_openpgp::Cert>,
    generation: Arc<tokio::sync::Semaphore>,
    release_workers: Arc<tokio::sync::Semaphore>,
    readiness: Arc<admission::Readiness>,
    issuance_token: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            release: None,
            expected_ca: None,
            generation: Arc::new(tokio::sync::Semaphore::new(1)),
            release_workers: Arc::new(tokio::sync::Semaphore::new(4)),
            readiness: Arc::new(admission::Readiness::default()),
            issuance_token: None,
        }
    }
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure issuance separately from public recovery; invalid configuration fails closed.
    pub fn set_issuance_token(&mut self, token: Option<String>) {
        self.issuance_token =
            token.filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    pub async fn ready(&self) -> bool {
        let expected = self.expected_ca.clone();
        let deadline = std::time::Instant::now() + service::REQUEST_BUDGET;
        self.readiness
            .check(deadline, move || {
                service::check_root(expected.as_ref(), deadline).is_ok()
            })
            .await
    }

    pub async fn check_ready(&self) -> Result<(), service::Error> {
        let expected = self.expected_ca.clone();
        let deadline = std::time::Instant::now() + service::REQUEST_BUDGET;
        service::blocking(deadline, move || {
            service::check_root(expected.as_ref(), deadline)
        })
        .await
    }

    pub(crate) async fn generate(
        &self,
        request: public_certificate_models::v1::PublicCertificateRequest,
    ) -> Result<public_certificate_models::PublicCertificateResponse, service::Error> {
        use dterror::ResultExt;
        let expected = self.expected_ca.clone();
        let deadline = std::time::Instant::now() + service::REQUEST_BUDGET;
        self.generate_with(deadline, move || {
            derivation::derive_public_certificate_until(
                request,
                *uuid::Uuid::new_v4().as_bytes(),
                expected.as_ref(),
                deadline,
            )
            .with_contexts((), "derive public certificates")
        })
        .await
    }

    async fn generate_with<T: Send + 'static>(
        &self,
        deadline: std::time::Instant,
        work: impl FnOnce() -> Result<T, service::Error> + Send + 'static,
    ) -> Result<T, service::Error> {
        use dterror::ResultExt;
        let permit = self
            .generation
            .clone()
            .try_acquire_owned()
            .with_contexts((), "certificate generation busy")?;
        service::blocking(deadline, move || {
            // A timed-out or disconnected caller must not admit another worker.
            let _permit = permit;
            service::remaining(deadline)?;
            work()
        })
        .await
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(routes::health))
        .route(
            "/v1/public-certificates",
            post(routes::derive_public_certificates).route_layer(
                axum::middleware::from_fn_with_state(state.clone(), admission::authenticate),
            ),
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

#[cfg(test)]
mod service_tests;
