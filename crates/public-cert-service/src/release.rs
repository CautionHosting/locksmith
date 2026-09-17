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

pub fn configured_authorizer() -> Result<Option<Authorizer>, Error> {
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
    Ok(Some(Authorizer::new(
        &config.rp_id,
        &config.origin,
        policy,
        ca,
    )?))
}
fn unavailable() -> (StatusCode, &'static str) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "share recovery is not configured",
    )
}
fn rejected(error: Error) -> (StatusCode, &'static str) {
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
    tokio::task::spawn_blocking(move || auth.begin(request))
        .await
        .map_err(|_| unavailable())?
        .map(Json)
        .map_err(rejected)
}
pub async fn prepare(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PrepareRequest>,
) -> Result<Json<Attested<Prepared>>, (StatusCode, &'static str)> {
    let auth = state.release.as_ref().ok_or_else(unavailable)?.clone();
    tokio::task::spawn_blocking(move || auth.prepare(request))
        .await
        .map_err(|_| unavailable())?
        .map(Json)
        .map_err(rejected)
}
pub async fn complete(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CompleteRequest>,
) -> Result<Json<SendSignedEncryptedShardRequest>, (StatusCode, &'static str)> {
    let auth = state.release.as_ref().ok_or_else(unavailable)?.clone();
    tokio::task::spawn_blocking(move || {
        auth.complete(request, |context, bundle, destination| {
            use dterror::ResultExt;
            let mut client = keyforkd_client::Client::discover_socket()
                .with_contexts((), "connect custody root")?;
            let path = derivation::certificate_path(
                context.organization_id,
                context.bundle_id,
                context.certificate_index,
            );
            let key = client
                .request_xprv::<keyfork_derive_openpgp::XPrvKey>(&path)
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
    .map_err(|_| unavailable())?
    .map(Json)
    .map_err(rejected)
}

#[cfg(all(test, feature = "unsafe-e2e"))]
#[path = "release_tests.rs"]
mod tests;
