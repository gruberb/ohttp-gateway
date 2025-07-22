use crate::AppState;
use axum::{
    extract::State,
    http::{HeaderName, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use tracing::info;

/// Handler for /ohttp-keys endpoint
/// Returns key configurations in the standard OHTTP format
pub async fn get_ohttp_keys(State(state): State<AppState>) -> Result<Response, StatusCode> {
    state.metrics.key_requests_total.inc();

    match state.key_manager.get_encoded_config().await {
        Ok(config_bytes) => {
            info!("Serving {} bytes of key configurations", config_bytes.len());

            // Calculate cache duration based on rotation interval
            let max_age = calculate_cache_max_age(&state);

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/ohttp-keys"),
                    (header::CACHE_CONTROL, &format!("public, max-age={max_age}")),
                    (HeaderName::from_static("x-content-type-options"), "nosniff"),
                ],
                config_bytes,
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!("Failed to encode key config: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Calculate appropriate cache duration for key configurations
fn calculate_cache_max_age(state: &AppState) -> u64 {
    // Cache for 10% of rotation interval, minimum 1 hour, maximum 24 hours
    let ten_percent = state.config.key_rotation_interval.as_secs() / 10;
    let one_hour = 3600;
    let twenty_four_hours = 86400;

    ten_percent.max(one_hour).min(twenty_four_hours)
}

/// Health check endpoint specifically for key management
pub async fn key_health_check(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state.key_manager.get_stats().await;

    let health_status = if stats.active_keys > 0 && stats.expired_keys == 0 {
        "healthy"
    } else if stats.active_keys > 0 {
        "degraded"
    } else {
        "unhealthy"
    };

    axum::Json(serde_json::json!({
        "status": health_status,
        "timestamp": Utc::now().to_rfc3339(),
        "key_stats": {
            "active_key_id": stats.active_key_id,
            "total_keys": stats.total_keys,
            "active_keys": stats.active_keys,
            "expired_keys": stats.expired_keys,
            "rotation_enabled": stats.auto_rotation_enabled,
            "rotation_interval_hours": stats.rotation_interval.as_secs() / 3600,
        }
    }))
}
