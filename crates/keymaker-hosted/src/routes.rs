use axum::Json;
use serde_json::{Value, json};

use keymaker_core::{GenerateQuorumError, GenerateQuorumErrorKind};
use keymaker_core::http::ApiError;
use keymaker_models::generate_quorum::{GenerateQuorumRequest, GenerateQuorumResponse};

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "keymaker-hosted" }))
}

/// Stateless quorum generation. No reboot, no shared state — fresh entropy per request.
#[axum::debug_handler]
#[tracing::instrument(skip_all)]
pub async fn generate_quorum(
    Json(request): Json<GenerateQuorumRequest>,
) -> Result<Json<GenerateQuorumResponse>, ApiError> {
    let response = tokio::task::spawn_blocking(move || keymaker_core::generate_quorum(request))
        .await
        .map_err(|e| ApiError(GenerateQuorumError::new(GenerateQuorumErrorKind::Shard, Some(e.into()))))?
        .map_err(ApiError)?;
    Ok(Json(response))
}
