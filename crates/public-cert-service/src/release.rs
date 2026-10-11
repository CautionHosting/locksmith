//! Optional release routes hosted beside certificate derivation, using the same Keyforkd root.
use crate::{AppState, derivation};
use axum::{Json, extract::State, http::StatusCode};
use locksmith::{
    models::SendSignedEncryptedShardRequest,
    release::{
        self, Attested, Authorizer, BeginRequest, Begun, CompleteRequest, Error, PrepareRequest,
        Prepared,
    },
};
use sequoia_openpgp::{Cert, parse::Parse};
use std::sync::Arc;

pub fn configured_authorizer() -> Result<Option<(Authorizer, Cert)>, Error> {
    use dterror::{FromContexts, ResultExt};
    // Opt-in keeps existing certificate-only deployments working.
    let Some(path) = std::env::var_os("CAUTION_RELEASE_CONFIG") else {
        return Ok(None);
    };
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        rp_id: String,
        origin: String,
        keymaker_policy_path: String,
        ca_cert_path: String,
    }
    let bytes = std::fs::read(path).with_contexts((), "read release configuration")?;
    let config: Config =
        serde_json::from_slice(&bytes).with_contexts((), "parse release configuration")?;
    let policy_text = std::fs::read_to_string(config.keymaker_policy_path)
        .with_contexts((), "read release Keymaker policy")?;
    let policy = locksmith::bundle::KeymakerPcrPolicy::from_json(&policy_text)
        .with_contexts((), "parse release Keymaker policy")?;
    let ca =
        Cert::from_bytes(&std::fs::read(config.ca_cert_path).with_contexts((), "read release CA")?)
            .map_err(|e| {
                Error::from_contexts(
                    (),
                    "parse release CA",
                    std::panic::Location::caller(),
                    e.into_boxed_dyn_error(),
                )
            })?;
    let authorizer = Authorizer::new(&config.rp_id, &config.origin, policy, ca.clone())?;
    Ok(Some((authorizer, ca)))
}
fn unavailable() -> (StatusCode, &'static str) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "share recovery is not configured",
    )
}
fn rejected(error: Error) -> (StatusCode, &'static str) {
    if error.is_busy() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "pending release capacity reached",
        );
    }
    tracing::warn!(%error, "share release rejected");
    (
        StatusCode::FORBIDDEN,
        "share release rejected; begin a fresh attempt",
    )
}
pub async fn begin(
    State(state): State<Arc<AppState>>,
    Json(request): Json<BeginRequest>,
) -> Result<Json<Attested<Begun>>, (StatusCode, &'static str)> {
    let auth = state.release.as_ref().ok_or_else(unavailable)?.clone();
    execute(
        &state,
        std::time::Instant::now() + crate::service::REQUEST_BUDGET,
        move || auth.begin(request),
    )
    .await
    .map(Json)
}
pub async fn prepare(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<Attested<Prepared>>, (StatusCode, &'static str)> {
    let auth = state.release.as_ref().ok_or_else(unavailable)?.clone();
    execute(
        &state,
        std::time::Instant::now() + crate::service::REQUEST_BUDGET,
        move || auth.prepare(request),
    )
    .await
    .map(Json)
}
pub async fn complete(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CompleteRequest>,
) -> Result<Json<SendSignedEncryptedShardRequest>, (StatusCode, &'static str)> {
    let auth = state.release.as_ref().ok_or_else(unavailable)?.clone();
    let deadline = std::time::Instant::now() + crate::service::REQUEST_BUDGET;
    execute(&state, deadline, move || {
        auth.complete(request, |context, bundle, destination| {
            use dterror::ResultExt;
            let path = derivation::certificate_path(
                context.organization_id,
                context.bundle_id,
                context.certificate_index,
            );
            let key = crate::service::derive_key(&path, deadline)
                .with_contexts((), "derive selected holder key")?;
            let private = keyfork_derive_openpgp::derive(
                &key,
                &derivation::public_certificate_key_flags(),
                &derivation::public_certificate_userid(context.certificate_index),
            )
            .with_contexts((), "derive selected PGP certificate")?;
            release::crypto::recrypt(context, bundle, destination, private)
        })
    })
    .await
    .map(Json)
}

async fn execute<T: Send + 'static>(
    state: &AppState,
    deadline: std::time::Instant,
    work: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, (StatusCode, &'static str)> {
    const UNAVAILABLE: (StatusCode, &str) = (
        StatusCode::SERVICE_UNAVAILABLE,
        "share recovery unavailable",
    );
    let permit = state
        .release_workers
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "share recovery busy"))?;
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::service::remaining(deadline).map_err(|_| UNAVAILABLE)?;
        let result = work().map_err(rejected)?;
        crate::service::remaining(deadline).map_err(|_| UNAVAILABLE)?;
        Ok(result)
    });
    tokio::time::timeout_at(deadline.into(), worker)
        .await
        .map_err(|_| UNAVAILABLE)?
        .map_err(|_| UNAVAILABLE)?
}

#[cfg(all(test, feature = "unsafe-e2e"))]
#[path = "release_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "release_admission_tests.rs"]
mod admission_tests;
