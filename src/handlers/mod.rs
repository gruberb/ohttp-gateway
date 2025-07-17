pub mod health;
pub mod keys;
pub mod ohttp;

use crate::state::AppState;
use axum::{
    routing::{get, post},
    Router,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        // OHTTP endpoints
        .route("/gateway", post(ohttp::handle_ohttp_request))
        .route("/ohttp-keys", get(keys::get_ohttp_keys))
        // Legacy endpoints for backward compatibility
        .route("/ohttp-configs", get(keys::get_legacy_ohttp_configs))
        // Health and monitoring
        .route("/health", get(health::health_check))
        .route("/health/keys", get(keys::key_health_check))
        .route("/metrics", get(health::metrics_handler))
}
