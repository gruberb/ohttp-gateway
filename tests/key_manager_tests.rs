use bhttp::Message;
use ohttp_gateway::key_manager::{CipherSuiteConfig, KeyManager, KeyManagerConfig};
use std::io::Cursor;
use std::time::Duration;
use tokio;

#[tokio::test]
async fn test_key_generation() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let stats = manager.get_stats().await;
    assert_eq!(stats.total_keys, 1);
    assert_eq!(stats.active_keys, 1);
    assert!(stats.active_key_id > 0); // Should have generated a key with ID > 0
}

#[tokio::test]
async fn test_key_generation_with_seed() {
    let config = KeyManagerConfig::default();
    let seed = vec![0u8; 32]; // 32 bytes of zeros for deterministic testing

    let manager = KeyManager::new_with_seed(config, seed).await.unwrap();
    let stats = manager.get_stats().await;

    assert_eq!(stats.total_keys, 1);
    assert_eq!(stats.active_keys, 1);
}

#[tokio::test]
async fn test_key_generation_with_insufficient_seed() {
    let config = KeyManagerConfig::default();
    let short_seed = vec![0u8; 16]; // Only 16 bytes - should fail

    let result = KeyManager::new_with_seed(config, short_seed).await;
    assert!(result.is_err());

    if let Err(e) = result {
        assert!(e.to_string().contains("Seed must be at least 32 bytes"));
    }
}

#[tokio::test]
async fn test_key_rotation() {
    let config = KeyManagerConfig {
        rotation_interval: Duration::from_secs(60),
        key_retention_period: Duration::from_secs(30),
        auto_rotation_enabled: true,
        ..Default::default()
    };

    let manager = KeyManager::new(config).await.unwrap();
    let initial_stats = manager.get_stats().await;

    // Rotate keys
    manager.rotate_keys().await.unwrap();

    let new_stats = manager.get_stats().await;
    assert_eq!(new_stats.total_keys, 2); // Old key + new key
    assert_ne!(new_stats.active_key_id, initial_stats.active_key_id);
}

#[tokio::test]
async fn test_get_current_server() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let server = manager.get_current_server().await;
    assert!(server.is_ok());
}

#[tokio::test]
async fn test_get_server_by_id() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let stats = manager.get_stats().await;
    let active_id = stats.active_key_id;

    // Should find the active key
    let server = manager.get_server_by_id(active_id).await;
    assert!(server.is_some());

    // Should not find non-existent key
    let non_existent = manager.get_server_by_id(active_id.wrapping_add(100)).await;
    assert!(non_existent.is_none());
}

#[tokio::test]
async fn test_should_rotate() {
    let config = KeyManagerConfig {
        rotation_interval: Duration::from_millis(100), // Very short for testing
        ..Default::default()
    };

    let manager = KeyManager::new(config).await.unwrap();

    // Should not need rotation immediately
    assert!(!manager.should_rotate().await);

    // Wait for the rotation interval to pass
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Now should need rotation
    assert!(manager.should_rotate().await);
}

#[tokio::test]
async fn test_get_encoded_config() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let encoded_config = manager.get_encoded_config().await.unwrap();

    // Should have some config data (no length prefix anymore)
    assert!(!encoded_config.is_empty());
    assert!(encoded_config.len() > 0);

    // The encoded config should be the raw config bytes without length prefix
    // We can't easily verify the exact content without duplicating the encoding logic,
    // but we can at least verify it's reasonable in size
    assert!(encoded_config.len() < 1000); // Reasonable upper bound
}

#[tokio::test]
async fn test_multiple_cipher_suites() {
    let config = KeyManagerConfig {
        cipher_suites: vec![
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
        ],
        ..Default::default()
    };

    let manager = KeyManager::new(config).await.unwrap();
    let stats = manager.get_stats().await;
    assert_eq!(stats.total_keys, 1);
}

#[tokio::test]
async fn test_cleanup_expired_keys() {
    let config = KeyManagerConfig {
        rotation_interval: Duration::from_millis(50),
        key_retention_period: Duration::from_millis(100),
        auto_rotation_enabled: false, // Manual control for testing
        ..Default::default()
    };

    let manager = KeyManager::new(config).await.unwrap();

    // Rotate to create an old key
    manager.rotate_keys().await.unwrap();

    let stats_after_rotation = manager.get_stats().await;
    assert_eq!(stats_after_rotation.total_keys, 2);

    // Wait for keys to expire and manually trigger cleanup
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Trigger another rotation which should clean up expired keys
    manager.rotate_keys().await.unwrap();

    let final_stats = manager.get_stats().await;
    // Should have cleaned up the expired key
    assert!(final_stats.total_keys <= 2);
}

#[tokio::test]
async fn test_bhttp_parsing() {
    // let data = &[
    //     2, 3, 71, 69, 84, 5, 104, 116, 116, 112, 115, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116,
    //     4, 47, 103, 101, 116, 10, 117, 115, 101, 114, 45, 97, 103, 101, 110, 116, 21, 79, 72, 84,
    //     84, 80, 45, 84, 101, 115, 116, 45, 67, 108, 105, 101, 110, 116, 47, 49, 46, 48, 6, 97, 99,
    //     99, 101, 112, 116, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115,
    //     111, 110, 0, 0,
    // ];
    // let mut cursor = std::io::Cursor::new(data);
    //
    // let m = Message::read_bhttp(&mut cursor).unwrap();
    //
    // println!("TEST {:?}", m);

    const REQUEST: &[u8] = &[
        2, 3, 71, 69, 84, 5, 104, 116, 116, 112, 115, 9, 108, 111, 99, 97, 108, 104, 111, 115, 116,
        4, 47, 103, 101, 116, 10, 117, 115, 101, 114, 45, 97, 103, 101, 110, 116, 21, 79, 72, 84,
        84, 80, 45, 84, 101, 115, 116, 45, 67, 108, 105, 101, 110, 116, 47, 49, 46, 48, 6, 97, 99,
        99, 101, 112, 116, 16, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 47, 106, 115,
        111, 110, 0, 0, 0,
    ];
    let m = Message::read_bhttp(&mut Cursor::new(REQUEST)).unwrap();
    assert!(m.header().get(b"accept").is_some());
}
