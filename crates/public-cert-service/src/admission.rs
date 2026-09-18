//! Issuance authentication and demand-driven, single-flight readiness.
use crate::AppState;
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

pub(crate) async fn authenticate(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = &state.issuance_token else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "certificate issuance is not configured",
        )
            .into_response();
    };
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let supplied = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let valid = supplied.is_some_and(|value| {
        use subtle::ConstantTimeEq;
        Sha256::digest(value.as_bytes())
            .ct_eq(&Sha256::digest(expected.as_bytes()))
            .into()
    });
    if !valid || values.next().is_some() {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            "issuance authentication required",
        )
            .into_response();
    }
    next.run(request).await
}

const CACHE_TTL: Duration = Duration::from_secs(2);
#[derive(Default)]
pub(crate) struct Readiness {
    state: Mutex<HealthState>,
}
#[derive(Default)]
struct HealthState {
    cached: Option<(Instant, bool)>,
    flight: Option<watch::Receiver<Option<bool>>>,
}
impl Readiness {
    pub(crate) async fn check(
        self: &Arc<Self>,
        deadline: Instant,
        work: impl FnOnce() -> bool + Send + 'static,
    ) -> bool {
        let mut receiver = {
            let Ok(mut state) = self.state.lock() else {
                return false;
            };
            if let Some((at, ready)) = state.cached {
                if at.elapsed() < CACHE_TTL {
                    return ready;
                }
            }
            if let Some(flight) = &state.flight {
                flight.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                state.flight = Some(receiver.clone());
                let cache = self.clone();
                // Detached supervisor owns the refresh through caller timeout/disconnect.
                tokio::spawn(async move {
                    let ready = tokio::task::spawn_blocking(work).await.unwrap_or(false);
                    if let Ok(mut state) = cache.state.lock() {
                        state.cached = Some((Instant::now(), ready));
                        state.flight = None;
                        let _ = sender.send(Some(ready));
                    }
                });
                receiver
            }
        };
        tokio::time::timeout_at(deadline.into(), async {
            loop {
                if let Some(ready) = *receiver.borrow_and_update() {
                    return ready;
                }
                if receiver.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false)
    }
    #[cfg(test)]
    pub(crate) fn expire(&self) {
        self.state.lock().unwrap().cached = None;
    }
}
