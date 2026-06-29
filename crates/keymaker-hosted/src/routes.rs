use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::{Value, json};

use keymaker_core::{GenerateQuorumError, GenerateQuorumErrorKind};
use keymaker_models::generate_quorum::{GenerateQuorumRequest, GenerateQuorumResponse};

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok", "service": "keymaker-hosted" }))
}

pub struct ApiError(GenerateQuorumError);

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status_code = match self.0.kind() {
            GenerateQuorumErrorKind::ParseCerts => StatusCode::BAD_REQUEST,
            GenerateQuorumErrorKind::Entropy
            | GenerateQuorumErrorKind::Shard
            | GenerateQuorumErrorKind::DeriveOpenPGPCert
            | GenerateQuorumErrorKind::SerializeOpenPGPCert => StatusCode::INTERNAL_SERVER_ERROR,
        };
        crate::middleware::error_handling::ErrorResponse::from_error(&self.0)
            .into_response(status_code)
    }
}

/// Stateless quorum generation. No reboot, no shared state — fresh entropy per request.
#[axum::debug_handler]
#[tracing::instrument(skip_all)]
pub async fn generate_quorum(
    Json(request): Json<GenerateQuorumRequest>,
) -> Result<Json<GenerateQuorumResponse>, ApiError> {
    let response = keymaker_core::generate_quorum(request).map_err(ApiError)?;
    Ok(Json(response))
}
