pub mod health;
pub mod keys;
pub mod ohttp;

use crate::state::AppState;
use axum::{
    Router,
    routing::{get, post},
};

pub fn routes() -> Router<AppState> {
    Router::new()
        // OHTTP endpoints
        .route("/gateway", post(ohttp::handle_ohttp_request))
        .route("/ohttp-configs", get(keys::get_ohttp_keys))
        // Health and monitoring
        .route("/health", get(health::health_check))
        .route("/health/keys", get(keys::key_health_check))
        .route("/metrics", get(health::metrics_handler))
}
