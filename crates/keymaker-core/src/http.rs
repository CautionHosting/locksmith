// ref: https://github.com/tokio-rs/axum/blob/main/examples/error-handling/src/main.rs
// nicked from bootproofd

use axum::{
    Json,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::error;

use crate::error::{GenerateQuorumError, GenerateQuorumErrorKind};

#[derive(Debug, serde::Serialize)]
pub struct ErrorResponse {
    errors: Vec<String>,
}

impl ErrorResponse {
    pub fn from_error<E: std::error::Error>(error: &E) -> Self {
        let mut errors = vec![error.to_string()];
        let mut source = error.source();
        while let Some(new_error) = source.take() {
            errors.push(new_error.to_string());
            source = new_error.source();
        }

        Self { errors }
    }

    pub fn into_response(self, status_code: impl Into<Option<StatusCode>>) -> Response {
        let status_code = status_code.into().unwrap_or(StatusCode::OK);

        let mut response = (status_code, Json(&self)).into_response();
        response.extensions_mut().insert(Arc::new(self));
        response
    }
}

pub async fn error_logger_middleware(request: Request, next: Next) -> Response {
    let uri = request.uri().clone();
    let response = next.run(request).await;

    if let Some(error_response) = response.extensions().get::<Arc<ErrorResponse>>() {
        // SAFETY: errors is instantiated to have at least one field when created by from_error,
        // and can't be created in any other way. we can safely assume &errors[1..] will not fail
        // with out of range start, even if it is an empty slice.
        let first_error = &error_response.errors[0];
        error!(?uri, "error in request: {first_error}");
        for error in &error_response.errors[1..] {
            error!(" - {error}");
        }
    }

    response
}

/// Newtype so callers can implement `IntoResponse` for `GenerateQuorumError` without
/// the orphan rule (both types live in this crate).
pub struct ApiError(pub GenerateQuorumError);

impl From<GenerateQuorumError> for ApiError {
    fn from(e: GenerateQuorumError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status_code = match self.0.kind() {
            GenerateQuorumErrorKind::ParseCerts => StatusCode::BAD_REQUEST,
            GenerateQuorumErrorKind::Entropy
            | GenerateQuorumErrorKind::Shard
            | GenerateQuorumErrorKind::DeriveOpenPGPCert
            | GenerateQuorumErrorKind::SerializeOpenPGPCert => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ErrorResponse::from_error(&self.0).into_response(status_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use crate::error::GenerateQuorumErrorKind;

    fn make_error(kind: GenerateQuorumErrorKind) -> GenerateQuorumError {
        GenerateQuorumError::new(kind, None)
    }

    #[test]
    fn error_response_captures_chain() {
        #[derive(Debug)]
        struct Inner;
        impl std::fmt::Display for Inner {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "inner cause")
            }
        }
        impl std::error::Error for Inner {}

        #[derive(Debug)]
        struct Outer(Inner);
        impl std::fmt::Display for Outer {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "outer")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let resp = ErrorResponse::from_error(&Outer(Inner));
        assert_eq!(resp.errors, vec!["outer", "inner cause"]);
    }

    #[tokio::test]
    async fn parse_certs_error_maps_to_400() {
        let err = make_error(GenerateQuorumErrorKind::ParseCerts);
        let response = ApiError(err).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["errors"].is_array());
    }

    #[tokio::test]
    async fn internal_errors_map_to_500() {
        for kind in [
            GenerateQuorumErrorKind::Entropy,
            GenerateQuorumErrorKind::Shard,
            GenerateQuorumErrorKind::DeriveOpenPGPCert,
            GenerateQuorumErrorKind::SerializeOpenPGPCert,
        ] {
            let label = format!("{kind:?}");
            let response = ApiError(make_error(kind)).into_response();
            assert_eq!(
                response.status(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{label} should be 500"
            );
        }
    }
}
