use axum::{body::Body, extract::Request, http::StatusCode, middleware::Next, response::Response};
use std::time::Instant;
use tracing::{Instrument, info, warn};
use uuid::Uuid;

pub async fn logging_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let request_id = Uuid::new_v4();
    let method = request.method().clone();
    let uri = request.uri().clone();
    let user_agent = request
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = %method,
        uri = %uri,
        user_agent = %user_agent
    );

    async move {
        let start = Instant::now();

        info!("Processing request");

        let response = next.run(request).await;

        let duration = start.elapsed();
        let status = response.status();

        if status.is_success() {
            info!(
                status = %status,
                duration_ms = duration.as_millis(),
                "Request completed successfully"
            );
        } else {
            warn!(
                status = %status,
                duration_ms = duration.as_millis(),
                "Request failed"
            );
        }

        Ok(response)
    }
    .instrument(span)
    .await
}
