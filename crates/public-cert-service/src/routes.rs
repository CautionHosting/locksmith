use std::sync::Arc;

use crate::{AppState, service};
use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use public_certificate_models::{PublicCertificateRequest, PublicCertificateResponse};
use serde_json::json;

pub async fn health(State(state): State<Arc<AppState>>) -> (StatusCode, Json<serde_json::Value>) {
    let ready = state.ready().await;
    (
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(json!({
            "status": if ready { "ready" } else { "unavailable" },
            "service": "public-cert-service",
        })),
    )
}

impl IntoResponse for service::Error {
    fn into_response(self) -> Response {
        tracing::warn!(%self, "public certificate derivation unavailable");
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "certificate generation unavailable"})),
        )
            .into_response()
    }
}

pub async fn derive_public_certificates(
    State(state): State<Arc<AppState>>,
    Json(request): Json<PublicCertificateRequest>,
) -> Result<Json<PublicCertificateResponse>, service::Error> {
    state.generate(request.to_latest()).await.map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn oversized_certificate_count_is_rejected_by_the_typed_request_boundary() {
        let mut state = AppState::new();
        state.set_issuance_token(Some("ab".repeat(32)));
        let app = crate::router(Arc::new(state));
        let request = json!({
            "version": "V1",
            "organization_id": [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            "certificate_count": 256,
        });

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn uuid_strings_are_rejected_by_the_typed_request_boundary() {
        let mut state = AppState::new();
        state.set_issuance_token(Some("ab".repeat(32)));
        let app = crate::router(Arc::new(state));
        let request = json!({
            "version": "V1",
            "organization_id": "00000000-0000-0000-0000-000000000001",
            "certificate_count": 1,
        });

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn client_supplied_bundle_id_is_rejected_by_the_typed_request_boundary() {
        let mut state = AppState::new();
        state.set_issuance_token(Some("ab".repeat(32)));
        let app = crate::router(Arc::new(state));
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
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn oversized_request_bodies_are_rejected_before_derivation() {
        let mut state = AppState::new();
        state.set_issuance_token(Some("ab".repeat(32)));
        let app = crate::router(Arc::new(state));
        let oversized_body = format!(
            "{{\"version\":\"V1\",\"organization_id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1],\"bundle_id\":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,2],\"certificate_count\":1,\"padding\":\"{}\"}}",
            "x".repeat(4097)
        );

        let response = app
            .oneshot(
                Request::post("/v1/public-certificates")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                    .body(Body::from(oversized_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
