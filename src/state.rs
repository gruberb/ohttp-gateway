use crate::{
    config::AppConfig,
    key_manager::{CipherSuiteConfig, KeyManager, KeyManagerConfig},
    metrics::AppMetrics,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub key_manager: Arc<KeyManager>,
    pub http_client: reqwest::Client,
    pub config: AppConfig,
    pub metrics: AppMetrics,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Configure key manager based on app config
        let key_manager_config = KeyManagerConfig {
            rotation_interval: config.key_rotation_interval,
            key_retention_period: config.key_retention_period,
            auto_rotation_enabled: config.key_rotation_enabled,
            cipher_suites: get_cipher_suites(&config),
        };

        // Initialize key manager with or without seed
        let key_manager = if let Some(seed_hex) = &config.seed_secret_key {
            let seed = hex::decode(seed_hex)?;
            Arc::new(KeyManager::new_with_seed(key_manager_config, seed).await?)
        } else {
            Arc::new(KeyManager::new(key_manager_config).await?)
        };

        // Create optimized HTTP client for backend requests
        let http_client = create_http_client(&config)?;

        let metrics = AppMetrics::default();

        Ok(Self {
            key_manager,
            http_client,
            config,
            metrics,
        })
    }
}

fn get_cipher_suites(config: &AppConfig) -> Vec<CipherSuiteConfig> {
    // Default cipher suites matching the Go implementation
    let mut suites = vec![
        CipherSuiteConfig {
            kem: "X25519_SHA256".to_string(),
            kdf: "HKDF_SHA256".to_string(),
            aead: "AES_128_GCM".to_string(),
        },
        CipherSuiteConfig {
            kem: "X25519_SHA256".to_string(),
            kdf: "HKDF_SHA256".to_string(),
            aead: "CHACHA20_POLY1305".to_string(),
        },
    ];

    // Add high-security suite if in production mode
    if !config.debug_mode {
        suites.push(CipherSuiteConfig {
            kem: "P256_SHA256".to_string(),
            kdf: "HKDF_SHA256".to_string(),
            aead: "AES_256_GCM".to_string(),
        });
    }

    suites
}

fn create_http_client(config: &AppConfig) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let mut client_builder = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .pool_max_idle_per_host(100)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .tcp_keepalive(std::time::Duration::from_secs(60))
        .tcp_nodelay(true)
        .user_agent("ohttp-gateway/1.0")
        .danger_accept_invalid_certs(config.debug_mode); // Only in debug mode

    // Configure proxy if needed
    if let Ok(proxy_url) = std::env::var("HTTP_PROXY") {
        client_builder = client_builder.proxy(reqwest::Proxy::http(proxy_url)?);
    }
    if let Ok(proxy_url) = std::env::var("HTTPS_PROXY") {
        client_builder = client_builder.proxy(reqwest::Proxy::https(proxy_url)?);
    }

    Ok(client_builder.build()?)
}
