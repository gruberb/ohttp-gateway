use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GatewayError {
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Backend error: {0}")]
    BackendError(String),

    #[error("Request too large: {0}")]
    RequestTooLarge(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            GatewayError::InvalidRequest(msg) => (StatusCode::BAD_REQUEST, "invalid_request", msg),
            GatewayError::DecryptionError(msg) => {
                (StatusCode::BAD_REQUEST, "decryption_error", msg)
            }
            GatewayError::EncryptionError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "encryption_error", msg)
            }
            GatewayError::BackendError(msg) => (StatusCode::BAD_GATEWAY, "backend_error", msg),
            GatewayError::RequestTooLarge(msg) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "request_too_large", msg)
            }
            GatewayError::ConfigurationError(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "configuration_error",
                msg,
            ),
            GatewayError::InternalError(msg) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", msg)
            }
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": message
            }
        }));

        (status, body).into_response()
    }
}
