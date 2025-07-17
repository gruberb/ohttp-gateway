use crate::{error::GatewayError, state::AppState};
use axum::{Json, extract::State};
use serde_json::json;
use std::time::Duration;

pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mut health_checks = vec![];

    // Check key manager health
    let key_status = match state.key_manager.get_encoded_config().await {
        Ok(config) if config.len() > 100 => "healthy",
        Ok(_) => "unhealthy",
        Err(_) => "unhealthy",
    };

    health_checks.push(json!({
        "component": "ohttp_keys",
        "status": key_status
    }));

    // Check backend connectivity - use the correct health endpoint
    let backend_health_url = format!("{}/health", state.config.backend_url);
    let backend_status = match state
        .http_client
        .get(&backend_health_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => "healthy",
        Ok(resp) => {
            tracing::warn!("Backend health check returned: {}", resp.status());
            "unhealthy"
        }
        Err(e) => {
            tracing::error!("Backend health check failed: {}", e);
            "unhealthy"
        }
    };

    health_checks.push(json!({
        "component": "backend",
        "status": backend_status,
        "url": backend_health_url
    }));

    let overall_status = if health_checks.iter().all(|c| c["status"] == "healthy") {
        "healthy"
    } else {
        "unhealthy"
    };

    Ok(Json(json!({
        "status": overall_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": health_checks,
        "version": env!("CARGO_PKG_VERSION")
    })))
}

pub async fn metrics_handler() -> Result<String, GatewayError> {
    use prometheus::{Encoder, TextEncoder};

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| GatewayError::InternalError(format!("Failed to encode metrics: {e}")))?;

    String::from_utf8(buffer).map_err(|e| {
        GatewayError::InternalError(format!("Failed to convert metrics to string: {e}"))
    })
}
