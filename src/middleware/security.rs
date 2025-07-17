use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{config::RateLimitConfig, state::AppState};

/// Rate limiter implementation
pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<HashMap<String, TokenBucket>>>,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn check_rate_limit(&self, key: &str) -> bool {
        let mut buckets = self.buckets.lock().await;
        let now = Instant::now();

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket {
                tokens: self.config.burst_size as f64,
                last_update: now,
            });

        // Calculate tokens to add based on time elapsed
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        let tokens_to_add = elapsed * (self.config.requests_per_second as f64);

        bucket.tokens = (bucket.tokens + tokens_to_add).min(self.config.burst_size as f64);
        bucket.last_update = now;

        // Check if we have tokens available
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Security middleware that adds various security headers and checks
pub async fn security_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Generate request ID for tracing
    let request_id = Uuid::new_v4();

    // Add security headers to the request context
    let mut request = request;
    request
        .headers_mut()
        .insert("x-request-id", request_id.to_string().parse().unwrap());

    let is_https = matches!(request.uri().scheme_str(), Some("https"));

    // Apply rate limiting if configured
    if let Some(rate_limit_config) = &state.config.rate_limit {
        let rate_limiter = RateLimiter::new(rate_limit_config.clone());

        let rate_limit_key = if rate_limit_config.by_ip {
            addr.ip().to_string()
        } else {
            "global".to_string()
        };

        if !rate_limiter.check_rate_limit(&rate_limit_key).await {
            warn!(
                "Rate limit exceeded for key: {}, request_id: {}",
                rate_limit_key, request_id
            );

            return Ok((
                StatusCode::TOO_MANY_REQUESTS,
                [
                    (
                        "X-RateLimit-Limit",
                        rate_limit_config.requests_per_second.to_string(),
                    ),
                    ("X-RateLimit-Remaining", "0".to_string()),
                    ("Retry-After", "1".to_string()),
                ],
                "Rate limit exceeded",
            )
                .into_response());
        }
    }

    // Process the request
    let mut response = next.run(request).await;

    // Add security headers to the response
    let headers = response.headers_mut();

    // Security headers
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("X-XSS-Protection", "1; mode=block".parse().unwrap());
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    headers.insert("X-Request-ID", request_id.to_string().parse().unwrap());

    // HSTS header for HTTPS connections
    if is_https {
        headers.insert(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains".parse().unwrap(),
        );
    }

    // Content Security Policy
    headers.insert(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none';"
            .parse()
            .unwrap(),
    );

    // Remove sensitive headers
    headers.remove("Server");
    headers.remove("X-Powered-By");

    Ok(response)
}

/// Middleware to validate and sanitize incoming requests
pub async fn request_validation_middleware(
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for required headers only on requests with bodies
    if matches!(
        request.method(),
        &axum::http::Method::POST | &axum::http::Method::PUT | &axum::http::Method::PATCH
    ) && !headers.contains_key(header::CONTENT_TYPE)
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Validate User-Agent
    if let Some(user_agent) = headers.get(header::USER_AGENT) {
        if let Ok(ua_str) = user_agent.to_str() {
            // Block known bad user agents
            if ua_str.is_empty() || ua_str.contains("bot") || ua_str.contains("crawler") {
                info!("Blocked suspicious user agent: {}", ua_str);
                return Err(StatusCode::FORBIDDEN);
            }
        }
    }

    Ok(next.run(request).await)
}
