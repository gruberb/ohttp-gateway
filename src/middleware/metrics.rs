// Additional metrics middleware if needed
use crate::state::AppState;
use axum::{body::Body, extract::Request, extract::State, middleware::Next, response::Response};

pub async fn metrics_middleware(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    state.metrics.active_connections.inc();

    let response = next.run(request).await;

    state.metrics.active_connections.dec();

    response
}
