use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use std::sync::Arc;

use crate::AppState;
use keymaker_core::{GenerateQuorumError, GenerateQuorumErrorKind};
use keymaker_models::generate_quorum::{GenerateQuorumRequest, GenerateQuorumResponse};

/// Newtype wrapper so we can implement axum's `IntoResponse` for core's error type
/// (orphan rule: the error now lives in `keymaker-core`).
pub struct ApiError(GenerateQuorumError);

impl From<GenerateQuorumError> for ApiError {
    fn from(e: GenerateQuorumError) -> Self {
        Self(e)
    }
}

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

/// Generate a new quorum, then trigger the self-nuke reboot (see `selfnuke` feature).
#[axum::debug_handler]
#[tracing::instrument(skip_all)]
pub async fn generate_quorum(
    State(app_state): State<Arc<AppState>>,
    Json(request): Json<GenerateQuorumRequest>,
) -> Result<Json<GenerateQuorumResponse>, ApiError> {
    #[cfg(not(feature = "selfnuke"))]
    let _ = &app_state;

    #[cfg(feature = "selfnuke")]
    tokio::task::spawn({
        // NOTE: The system should be terminated after this route has been called, regardless of
        // whether it was successful or not. We set a deadline of 10 seconds to complete the
        // operation and send the response to the client before rebooting. No one else will be able
        // to obtain a reboot permit, as we purposefully forget the permit without releasing it.
        let reboot_permit = app_state
            .reboot_permit
            .acquire()
            .await
            .expect("semaphore is never closed");
        std::mem::forget(reboot_permit);
        async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT)
                .expect("should be able to reboot system");
        }
    });

    let response = keymaker_core::generate_quorum(request)?;
    Ok(Json(response))
}
