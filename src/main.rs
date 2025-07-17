mod config;
mod error;
mod handlers;
mod key_manager;
mod metrics;
mod middleware;
mod state;

use crate::config::{AppConfig, LogFormat};
use crate::state::AppState;
use axum::{Router, middleware as axum_middleware};
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
    let app = create_router(app_state.clone(), &config);

    // Parse socket address
    let addr: SocketAddr = config.listen_addr.parse()?;
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

fn create_router(app_state: AppState, config: &AppConfig) -> Router {
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
            .layer(create_cors_layer(config)),
    );

    app.with_state(app_state)
}

fn create_cors_layer(config: &AppConfig) -> CorsLayer {
    if config.debug_mode {
        // Permissive CORS in debug mode
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        // Restrictive CORS in production
        CorsLayer::new()
            .allow_origin([
                "https://example.com".parse().unwrap(),
                // Add your allowed origins here
            ])
            .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
            .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::ACCEPT])
            .max_age(Duration::from_secs(3600))
    }
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

    #[test]
    fn test_config_loading() {
        // Test that default config loads successfully
        let config = AppConfig::default();
        assert!(!config.debug_mode);
        assert!(config.key_rotation_enabled);
    }
}
