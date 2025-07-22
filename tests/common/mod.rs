//! Test utilities and common code for integration tests
#![cfg(test)]
#![allow(dead_code)]

use ohttp::{
    KeyConfig, Server as OhttpServer, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Test constants matching Go implementation
pub const LEGACY_KEY_ID: u8 = 0x00;
pub const CURRENT_KEY_ID: u8 = 0x01;
pub const FORBIDDEN_TARGET: &str = "forbidden.example";
pub const ALLOWED_TARGET: &str = "allowed.example";
pub const GATEWAY_DEBUG: bool = true;
pub const BINARY_HTTP_GATEWAY_ENDPOINT: &str = "/binary-http-gateway";

// Mock metrics for testing
#[derive(Debug, Clone, Default)]
pub struct MockMetrics {
    pub event_name: String,
    pub result_labels: Arc<RwLock<HashMap<String, bool>>>,
}

impl MockMetrics {
    pub fn new(event_name: String) -> Self {
        Self {
            event_name,
            result_labels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn response_status(&self, prefix: &str, status: u16) {
        self.fire(&format!("{}_response_status_{}", prefix, status))
            .await;
    }

    pub async fn fire(&self, result: &str) {
        let mut labels = self.result_labels.write().await;
        if labels.contains_key(result) {
            panic!("Metrics.fire called twice for the same result: {}", result);
        }
        labels.insert(result.to_string(), true);
    }

    pub async fn contains_result(&self, result: &str) -> bool {
        let labels = self.result_labels.read().await;
        labels.contains_key(result)
    }
}

#[derive(Debug, Default)]
pub struct MockMetricsFactory {
    pub metrics: Arc<RwLock<Vec<MockMetrics>>>,
}

impl MockMetricsFactory {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn create(&self, event_name: String) -> MockMetrics {
        let metrics = MockMetrics::new(event_name);
        let mut metrics_vec = self.metrics.write().await;
        metrics_vec.push(metrics.clone());
        metrics
    }

    pub async fn get_metrics_for_event(&self, event_name: &str) -> Option<MockMetrics> {
        let metrics_vec = self.metrics.read().await;
        metrics_vec
            .iter()
            .find(|m| m.event_name == event_name)
            .cloned()
    }
}

// Test key configuration similar to Go's createGateway
pub fn create_test_key_configs() -> Result<(KeyConfig, KeyConfig), Box<dyn std::error::Error>> {
    // Legacy configuration (X25519 only)
    let legacy_config = KeyConfig::new(
        LEGACY_KEY_ID,
        Kem::X25519Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
    )?;

    // Current configuration (for testing - in real implementation would be post-quantum)
    let current_config = KeyConfig::new(
        CURRENT_KEY_ID,
        Kem::X25519Sha256, // ohttp crate limitation - would be KEM_X25519_KYBER768_DRAFT00
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
    )?;

    Ok((current_config, legacy_config))
}

// Create test servers from configs
pub fn create_test_servers() -> Result<(OhttpServer, OhttpServer), Box<dyn std::error::Error>> {
    let (current_config, legacy_config) = create_test_key_configs()?;

    let current_server = OhttpServer::new(current_config)?;
    let legacy_server = OhttpServer::new(legacy_config)?;

    Ok((current_server, legacy_server))
}

// Mock HTTP request handler for testing
#[derive(Debug, Clone)]
pub struct MockHTTPRequestHandler;

impl MockHTTPRequestHandler {
    pub fn handle(&self, url: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Echo the URL back for testing
        Ok(url.to_string())
    }
}

// Helper function to create test binary HTTP messages
pub fn create_test_binary_http_message() -> Vec<u8> {
    // Simple test message similar to Go's {0xCA, 0xFE}
    vec![0xCA, 0xFE]
}

// Helper to validate cache control headers
pub fn validate_cache_control_header(header_value: &str) -> Result<(), String> {
    if !header_value.starts_with("max-age=") || !header_value.ends_with(", private") {
        return Err(format!("Invalid cache-control format: {}", header_value));
    }

    let max_age_str = header_value
        .strip_prefix("max-age=")
        .and_then(|s| s.strip_suffix(", private"))
        .ok_or("Failed to parse max-age")?;

    let max_age: u32 = max_age_str
        .parse()
        .map_err(|_| "max-age should be a number")?;

    const TWELVE_HOURS: u32 = 12 * 3600;
    const TWENTY_FOUR_HOURS: u32 = 24 * 3600;

    if max_age < TWELVE_HOURS || max_age > TWELVE_HOURS + TWENTY_FOUR_HOURS {
        return Err(format!(
            "max-age {} should be between 12 and 36 hours",
            max_age
        ));
    }

    Ok(())
}

// Test result assertion helpers
pub async fn assert_metrics_contains_result(
    factory: &MockMetricsFactory,
    event: &str,
    result: &str,
) -> Result<(), String> {
    if let Some(metrics) = factory.get_metrics_for_event(event).await {
        if !metrics.contains_result(result).await {
            return Err(format!("Expected event {}/{} was not fired", event, result));
        }
        Ok(())
    } else {
        Err(format!("No metrics found for event: {}", event))
    }
}

pub fn assert_body_contains_error(body: &[u8], expected_text: &str) -> Result<(), String> {
    let body_str = String::from_utf8_lossy(body);
    if !body_str.contains(expected_text) {
        return Err(format!(
            "Failed to return expected text ({}) in response. Body text is: {}",
            expected_text, body_str
        ));
    }
    Ok(())
}
