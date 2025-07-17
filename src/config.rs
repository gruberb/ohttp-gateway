use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AppConfig {
    // Server configuration
    pub listen_addr: String,
    pub backend_url: String,
    pub request_timeout: Duration,
    pub max_body_size: usize,

    // Key management
    pub key_rotation_interval: Duration,
    pub key_retention_period: Duration,
    pub key_rotation_enabled: bool,

    // Security configuration
    pub allowed_target_origins: Option<HashSet<String>>,
    pub target_rewrites: Option<TargetRewriteConfig>,
    pub rate_limit: Option<RateLimitConfig>,

    // Operational configuration
    pub metrics_enabled: bool,
    pub debug_mode: bool,
    pub log_format: LogFormat,
    pub log_level: String,

    // OHTTP specific
    pub custom_request_type: Option<String>,
    pub custom_response_type: Option<String>,
    pub seed_secret_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetRewriteConfig {
    pub rewrites: std::collections::HashMap<String, TargetRewrite>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TargetRewrite {
    pub scheme: String,
    pub host: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub by_ip: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Default,
    Json,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8080".to_string(),
            backend_url: "http://localhost:8080".to_string(),
            request_timeout: Duration::from_secs(30),
            max_body_size: 10 * 1024 * 1024, // 10MB
            key_rotation_interval: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            key_retention_period: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            key_rotation_enabled: true,
            allowed_target_origins: None,
            target_rewrites: None,
            rate_limit: None,
            metrics_enabled: true,
            debug_mode: false,
            log_format: LogFormat::Default,
            log_level: "info".to_string(),
            custom_request_type: None,
            custom_response_type: None,
            seed_secret_key: None,
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = Self::default();

        // Basic configuration
        if let Ok(addr) = std::env::var("LISTEN_ADDR") {
            config.listen_addr = addr;
        }

        if let Ok(url) = std::env::var("BACKEND_URL") {
            config.backend_url = url;
        }

        if let Ok(timeout) = std::env::var("REQUEST_TIMEOUT") {
            config.request_timeout = Duration::from_secs(timeout.parse()?);
        }

        if let Ok(size) = std::env::var("MAX_BODY_SIZE") {
            config.max_body_size = size.parse()?;
        }

        // Key management
        if let Ok(interval) = std::env::var("KEY_ROTATION_INTERVAL") {
            config.key_rotation_interval = Duration::from_secs(interval.parse()?);
        }

        if let Ok(period) = std::env::var("KEY_RETENTION_PERIOD") {
            config.key_retention_period = Duration::from_secs(period.parse()?);
        }

        if let Ok(enabled) = std::env::var("KEY_ROTATION_ENABLED") {
            config.key_rotation_enabled = enabled.parse()?;
        }

        // Security configuration
        if let Ok(origins) = std::env::var("ALLOWED_TARGET_ORIGINS") {
            let origins_set: HashSet<String> = origins
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if !origins_set.is_empty() {
                config.allowed_target_origins = Some(origins_set);
            }
        }

        if let Ok(rewrites_json) = std::env::var("TARGET_REWRITES") {
            let rewrites: std::collections::HashMap<String, TargetRewrite> =
                serde_json::from_str(&rewrites_json)?;
            config.target_rewrites = Some(TargetRewriteConfig { rewrites });
        }

        // Rate limiting
        if let Ok(rps) = std::env::var("RATE_LIMIT_RPS") {
            let rate_limit = RateLimitConfig {
                requests_per_second: rps.parse()?,
                burst_size: std::env::var("RATE_LIMIT_BURST")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(100),
                by_ip: std::env::var("RATE_LIMIT_BY_IP")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(true),
            };
            config.rate_limit = Some(rate_limit);
        }

        // Operational configuration
        if let Ok(enabled) = std::env::var("METRICS_ENABLED") {
            config.metrics_enabled = enabled.parse()?;
        }

        if let Ok(debug) = std::env::var("GATEWAY_DEBUG") {
            config.debug_mode = debug.parse()?;
        }

        if let Ok(format) = std::env::var("LOG_FORMAT") {
            config.log_format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                _ => LogFormat::Default,
            };
        }

        if let Ok(level) = std::env::var("LOG_LEVEL") {
            config.log_level = level;
        }

        // OHTTP specific
        if let Ok(req_type) = std::env::var("CUSTOM_REQUEST_TYPE") {
            config.custom_request_type = Some(req_type);
        }

        if let Ok(resp_type) = std::env::var("CUSTOM_RESPONSE_TYPE") {
            config.custom_response_type = Some(resp_type);
        }

        if let Ok(seed) = std::env::var("SEED_SECRET_KEY") {
            config.seed_secret_key = Some(seed);
        }

        // Validate configuration
        config.validate()?;

        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Validate key rotation settings
        if self.key_retention_period > self.key_rotation_interval {
            return Err("Key retention period cannot be longer than rotation interval".into());
        }

        // Validate custom content types
        match (&self.custom_request_type, &self.custom_response_type) {
            (Some(req), Some(resp)) if req == resp => {
                return Err("Request and response content types must be different".into());
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err("Both custom request and response types must be specified".into());
            }
            _ => {}
        }

        // Validate seed if provided
        if let Some(seed) = &self.seed_secret_key {
            let decoded =
                hex::decode(seed).map_err(|_| "SEED_SECRET_KEY must be a hex-encoded string")?;

            if decoded.len() < 32 {
                return Err("SEED_SECRET_KEY must be at least 32 bytes (64 hex characters)".into());
            }
        }

        Ok(())
    }

    /// Check if a target origin is allowed
    pub fn is_origin_allowed(&self, origin: &str) -> bool {
        match &self.allowed_target_origins {
            Some(allowed) => allowed.contains(origin),
            None => true, // No restrictions if not configured
        }
    }

    /// Get rewrite configuration for a host
    pub fn get_rewrite(&self, host: &str) -> Option<&TargetRewrite> {
        self.target_rewrites
            .as_ref()
            .and_then(|config| config.rewrites.get(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppConfig::default();
        assert_eq!(config.listen_addr, "0.0.0.0:8080");
        assert!(config.key_rotation_enabled);
    }

    #[test]
    fn test_validation_key_periods() {
        let mut config = AppConfig::default();
        config.key_retention_period = Duration::from_secs(100);
        config.key_rotation_interval = Duration::from_secs(50);

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_origin_allowed() {
        let mut config = AppConfig::default();
        config.allowed_target_origins = Some(
            vec!["example.com".to_string(), "test.com".to_string()]
                .into_iter()
                .collect(),
        );

        assert!(config.is_origin_allowed("example.com"));
        assert!(!config.is_origin_allowed("forbidden.com"));
    }
}
