use hyper::StatusCode;
use rand::Rng;

use ohttp_gateway::{key_manager::KeyManager, key_manager::KeyManagerConfig};

mod common;

use common::{LEGACY_KEY_ID, validate_cache_control_header};

// Mock HTTP response structure for testing
struct MockResponse {
    status: StatusCode,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
}

impl MockResponse {
    fn new(status: StatusCode, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: std::collections::HashMap::new(),
            body,
        }
    }

    fn add_header(&mut self, name: &str, value: &str) {
        self.headers.insert(name.to_string(), value.to_string());
    }

    fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name)
    }
}

// Mock config handler - adapt this to match your actual HTTP handler structure
async fn mock_config_handler(
    manager: &KeyManager,
) -> Result<MockResponse, Box<dyn std::error::Error>> {
    // Generate random cache age between 12-36 hours (mirroring Go implementation)
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let twelve_hours = 12 * 3600;
    let twenty_four_hours = 24 * 3600;
    let max_age = twelve_hours + rng.gen_range(0..twenty_four_hours);

    let encoded_config = manager.get_encoded_config().await?;

    let mut response = MockResponse::new(StatusCode::OK, encoded_config);
    response.add_header("Cache-Control", &format!("max-age={}, private", max_age));
    response.add_header("Content-Type", "application/ohttp-keys");

    Ok(response)
}

async fn mock_legacy_config_handler(
    manager: &KeyManager,
    _key_id: u8,
) -> Result<MockResponse, Box<dyn std::error::Error>> {
    // This would need to be implemented based on your legacy config support
    // For now, return a simple implementation
    let encoded_config = manager.get_encoded_config().await?;

    let mut rng = rand::thread_rng();
    let twelve_hours = 12 * 3600;
    let twenty_four_hours = 24 * 3600;
    let max_age = twelve_hours + rng.gen_range(0..twenty_four_hours);

    let mut response = MockResponse::new(StatusCode::OK, encoded_config);
    response.add_header("Cache-Control", &format!("max-age={}, private", max_age));

    Ok(response)
}

#[tokio::test]
async fn test_config_handler() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let response = mock_config_handler(&manager).await.unwrap();

    // Check status
    assert_eq!(response.status, StatusCode::OK);

    // Check headers
    assert_eq!(
        response.get_header("Content-Type").unwrap(),
        "application/ohttp-keys"
    );

    let cache_control = response.get_header("Cache-Control").unwrap();
    validate_cache_control_header(cache_control).unwrap();

    // Check body is not empty and has expected structure
    assert!(!response.body.is_empty());
    assert!(response.body.len() >= 4); // At least length prefix + some config data
}

#[tokio::test]
async fn test_legacy_config_handler() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let response = mock_legacy_config_handler(&manager, LEGACY_KEY_ID)
        .await
        .unwrap();

    // Check status
    assert_eq!(response.status, StatusCode::OK);

    // Check cache control header exists and is valid
    let cache_control = response.get_header("Cache-Control").unwrap();
    validate_cache_control_header(cache_control).unwrap();

    // Check body
    assert!(!response.body.is_empty());
}

#[tokio::test]
async fn test_config_handler_multiple_keys() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    // Add another key through rotation
    manager.rotate_keys().await.unwrap();

    let response = mock_config_handler(&manager).await.unwrap();

    assert_eq!(response.status, StatusCode::OK);

    // Body should be larger with multiple keys
    assert!(response.body.len() >= 8); // At least 2 key configs
}

#[tokio::test]
async fn test_config_consistency() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    // Get config multiple times
    let response1 = mock_config_handler(&manager).await.unwrap();
    let response2 = mock_config_handler(&manager).await.unwrap();

    // Both responses should be successful
    assert_eq!(response1.status, StatusCode::OK);
    assert_eq!(response2.status, StatusCode::OK);

    // Key content should be the same (though cache headers may differ)
    // Note: In a real implementation, you might want to test deterministic key generation
    assert_eq!(response1.body.len(), response2.body.len());
}

#[tokio::test]
async fn test_config_with_deterministic_seed() {
    let config = KeyManagerConfig::default();
    let seed = vec![0x42u8; 32]; // Fixed seed for deterministic keys

    let manager1 = KeyManager::new_with_seed(config.clone(), seed.clone())
        .await
        .unwrap();
    let manager2 = KeyManager::new_with_seed(config, seed).await.unwrap();

    let response1 = mock_config_handler(&manager1).await.unwrap();
    let response2 = mock_config_handler(&manager2).await.unwrap();

    // Both should succeed
    assert_eq!(response1.status, StatusCode::OK);
    assert_eq!(response2.status, StatusCode::OK);

    // With the same seed, the key configurations should be identical
    // This now works because we're using KeyConfig::derive() for deterministic generation
    assert_eq!(response1.body, response2.body);

    // Also verify the bodies are not empty and have valid structure
    assert!(!response1.body.is_empty());
    assert!(response1.body.len() >= 4);
}

#[tokio::test]
async fn test_cache_control_randomization() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let mut max_ages = std::collections::HashSet::new();

    // Generate multiple responses and collect max-age values
    for _ in 0..10 {
        let response = mock_config_handler(&manager).await.unwrap();
        let cache_control = response.get_header("Cache-Control").unwrap();

        // Extract max-age value
        let max_age_str = cache_control
            .strip_prefix("max-age=")
            .and_then(|s| s.strip_suffix(", private"))
            .unwrap();
        let max_age: u32 = max_age_str.parse().unwrap();

        max_ages.insert(max_age);
    }

    // Should have some variation in max-age values (randomization)
    // Note: This test might occasionally fail due to randomness, but should usually pass
    assert!(
        max_ages.len() > 1,
        "Cache-Control max-age should be randomized"
    );
}
