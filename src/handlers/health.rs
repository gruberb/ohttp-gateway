use crate::{error::GatewayError, state::AppState};
use axum::{Json, extract::State};
use serde_json::json;
use std::time::Duration;

pub async fn health_check(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let mut health_checks = vec![];

    // Check key manager health
    let stats = state.key_manager.get_stats().await;
    let key_status = if stats.active_keys > 0 {
        "healthy"
    } else {
        "unhealthy"
    };

    health_checks.push(json!({
        "component": "ohttp_keys",
        "status": key_status
    }));

    // Check backend connectivity - any HTTP response means reachable
    let backend_url = state.config.backend_url.clone();
    let (backend_status, backend_error) = match state
        .http_client
        .head(&backend_url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
    {
        Ok(_) => ("healthy", None),
        Err(e) => {
            tracing::error!("Backend health check failed: {}", e);
            ("unhealthy", Some(e.to_string()))
        }
    };

    let mut backend_check = json!({
        "component": "backend",
        "status": backend_status,
        "url": backend_url
    });
    if let Some(err) = backend_error {
        backend_check["error"] = json!(err);
    }
    health_checks.push(backend_check);

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
