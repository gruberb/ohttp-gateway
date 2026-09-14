use axum::{Router, middleware as axum_middleware};
use ohttp_gateway::{AppConfig, AppState, config::LogFormat, handlers, middleware};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::signal;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load configuration first
    let config = AppConfig::from_env()?;
    let cors = create_cors_layer(
        &config,
        std::env::var("CORS_ALLOWED_ORIGINS").ok().as_deref(),
    )?;

    // Initialize tracing based on config
    initialize_tracing(&config);

    info!("Starting OHTTP Gateway v{}", env!("CARGO_PKG_VERSION"));
    info!("Configuration loaded: {:?}", config);

    // Initialize application state
    let app_state = AppState::new(config.clone()).await?;

    // Start key rotation scheduler
    if config.key_rotation_enabled {
        info!("Starting automatic key rotation scheduler");
        app_state
            .key_manager
            .clone()
            .start_rotation_scheduler()
            .await;
    } else {
        warn!("Automatic key rotation is disabled");
    }

    // Create router
    let app = create_router(app_state.clone(), cors);

    // Parse socket address
    let addr: SocketAddr = config.port.parse()?;
    let listener = TcpListener::bind(addr).await?;

    info!("OHTTP Gateway listening on {}", addr);
    info!("Backend URL: {}", config.backend_url);

    if let Some(allowed) = &config.allowed_target_origins {
        info!("Allowed origins: {:?}", allowed);
    } else {
        warn!("No origin restrictions configured - all targets allowed");
    }

    // Start server with graceful shutdown
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("Server stopped gracefully");
    Ok(())
}

fn initialize_tracing(config: &AppConfig) {
    use tracing_subscriber::{EnvFilter, fmt};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&config.log_level));

    match config.log_format {
        LogFormat::Json => {
            fmt()
                .json()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(config.debug_mode)
                .with_line_number(config.debug_mode)
                .init();
        }
        LogFormat::Default => {
            fmt()
                .with_env_filter(env_filter)
                .with_target(true)
                .with_thread_ids(true)
                .with_file(config.debug_mode)
                .with_line_number(config.debug_mode)
                .init();
        }
    }
}

fn create_router(app_state: AppState, cors: CorsLayer) -> Router {
    let mut app = Router::new();

    // Add routes
    app = app.merge(handlers::routes());

    // Add middleware layers (order matters - first added is executed last)
    app = app.layer(
        tower::ServiceBuilder::new()
            // Outer layers (executed first on request, last on response)
            .layer(TraceLayer::new_for_http())
            .layer(CompressionLayer::new())
            .layer(TimeoutLayer::new(Duration::from_secs(60)))
            // Security middleware
            .layer(axum_middleware::from_fn_with_state(
                app_state.clone(),
                middleware::security::security_middleware,
            ))
            // Request validation
            .layer(axum_middleware::from_fn(
                middleware::security::request_validation_middleware,
            ))
            // Logging middleware
            .layer(axum_middleware::from_fn_with_state(
                app_state.clone(),
                middleware::logging::logging_middleware,
            ))
            // Metrics middleware
            .layer(axum_middleware::from_fn_with_state(
                app_state.clone(),
                middleware::metrics::metrics_middleware,
            ))
            // CORS configuration
            .layer(cors),
    );

    app.with_state(app_state)
}

fn create_cors_layer(
    config: &AppConfig,
    configured_origins: Option<&str>,
) -> Result<CorsLayer, Box<dyn std::error::Error>> {
    if config.debug_mode && configured_origins.is_none() {
        return Ok(CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any));
    }

    // Preserve the deployed default when the environment variable is unset.
    let mut origins = Vec::new();
    for origin in configured_origins
        .unwrap_or("https://example.com")
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        let url = reqwest::Url::parse(origin)
            .map_err(|_| format!("Invalid CORS_ALLOWED_ORIGINS origin: {origin}"))?;
        if !matches!(url.scheme(), "http" | "https") || url.origin().ascii_serialization() != origin
        {
            return Err(format!(
                "CORS_ALLOWED_ORIGINS requires exact HTTP(S) origins without paths: {origin}"
            )
            .into());
        }
        origins.push(origin.parse::<axum::http::HeaderValue>()?);
    }

    Ok(CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
        .max_age(Duration::from_secs(3600)))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, starting graceful shutdown");
        },
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, header},
    };
    use tower::Service;

    #[tokio::test]
    async fn cors_configuration() {
        for (debug, allowed, origin, expected) in [
            (
                false,
                None,
                "https://example.com",
                Some("https://example.com"),
            ),
            (false, None, "https://other.example.com", None),
            (true, None, "https://other.example.com", Some("*")),
            (false, Some(""), "https://example.com", None),
            (true, Some(""), "https://example.com", None),
            (
                false,
                Some(" https://app.example.com, http://localhost:3000 "),
                "https://app.example.com",
                Some("https://app.example.com"),
            ),
            (
                false,
                Some("https://app.example.com,http://localhost:3000"),
                "http://localhost:3000",
                Some("http://localhost:3000"),
            ),
            (
                false,
                Some("https://app.example.com"),
                "https://other.example.com",
                None,
            ),
            (
                true,
                Some("https://app.example.com"),
                "https://other.example.com",
                None,
            ),
        ] {
            let config = AppConfig {
                debug_mode: debug,
                ..Default::default()
            };
            let mut app = Router::new()
                .route("/gateway", axum::routing::post(|| async { "ok" }))
                .layer(create_cors_layer(&config, allowed).unwrap());
            for method in ["POST", "OPTIONS"] {
                let request = Request::builder()
                    .method(method)
                    .uri("/gateway")
                    .header(header::ORIGIN, origin)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "content-type")
                    .body(Body::empty())
                    .unwrap();
                let response = app.call(request).await.unwrap();
                assert_eq!(
                    response
                        .headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .map(|v| v.to_str().unwrap()),
                    expected
                );
                if method == "OPTIONS" && expected.is_some() && !debug {
                    assert_eq!(
                        response.headers()[header::ACCESS_CONTROL_ALLOW_METHODS],
                        "GET,POST"
                    );
                    assert_eq!(
                        response.headers()[header::ACCESS_CONTROL_ALLOW_HEADERS],
                        "content-type,accept"
                    );
                    assert_eq!(response.headers()[header::ACCESS_CONTROL_MAX_AGE], "3600");
                }
            }
        }
        for origin in [
            "*",
            "null",
            "example.com",
            "https://app.example.com/",
            "https://app.example.com/path",
            "https://user@app.example.com",
            "https://app.example.com?x=1",
            "ftp://app.example.com",
        ] {
            assert!(
                create_cors_layer(&AppConfig::default(), Some(origin)).is_err(),
                "{origin}"
            );
        }
    }
}
