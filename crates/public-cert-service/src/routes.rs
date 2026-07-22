use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use public_certificate_models::{PublicCertificateRequest, PublicCertificateResponse};
use serde_json::json;
use uuid::Uuid;

use crate::{AppState, derivation};

pub async fn health(State(_state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ready",
        "service": "public-cert-service",
    }))
}

#[derive(Debug, thiserror::Error)]
pub enum DerivePublicCertificatesError {
    #[error("failed to derive public certificate bundle")]
    Derive(#[from] derivation::DerivePublicCertificateError),
}

impl IntoResponse for DerivePublicCertificatesError {
    fn into_response(self) -> Response {
        tracing::warn!(error = ?self, "public certificate derivation failed");
        let status = match self {
            Self::Derive(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({
            "error": self.to_string(),
        }));

        (status, body).into_response()
    }
}

pub async fn derive_public_certificates(
    State(_state): State<Arc<AppState>>,
    Json(request): Json<PublicCertificateRequest>,
) -> Result<Json<PublicCertificateResponse>, DerivePublicCertificatesError> {
    let latest = request.to_latest();
    let bundle_id = *Uuid::new_v4().as_bytes();
    Ok(Json(derivation::derive_public_certificate(
        latest, bundle_id,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_reports_ready_without_sensitive_recovery_details() {
        let app = crate::router(Arc::new(AppState::new()));

        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["status"], "ready");
        assert!(body.get("shard_count").is_none());
        assert!(body.get("holder").is_none());
    }

    #[tokio::test]
    async fn oversized_certificate_count_is_rejected_by_the_typed_request_boundary() {
        let app = crate::router(Arc::new(AppState::new()));
        let request = json!({
            "version": "V1",
            "organization_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "certificate_count": 256,
        });

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn uuid_strings_are_rejected_by_the_typed_request_boundary() {
        let app = crate::router(Arc::new(AppState::new()));
        let request = json!({
            "version": "V1",
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "certificate_count": 1,
        });

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn client_supplied_bundle_id_is_rejected_by_the_typed_request_boundary() {
        let app = crate::router(Arc::new(AppState::new()));
        let request = json!({
            "version": "V1",
            "organization_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "bundle_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            "certificate_count": 1,
        });

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn oversized_request_bodies_are_rejected_before_derivation() {
        let app = crate::router(Arc::new(AppState::new()));
        let oversized_body = format!(
            "{{\"version\":\"V1\",\"organization_id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],\"bundle_id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],\"certificate_count\":1,\"padding\":\"{}\"}}",
            "x".repeat(4097)
        );

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .body(Body::from(oversized_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
