use std::time::Duration;

use ohttp_gateway::{key_manager::KeyManager, key_manager::KeyManagerConfig};

#[tokio::test]
async fn test_key_rotation_during_requests() {
    let config = KeyManagerConfig {
        rotation_interval: Duration::from_millis(100),
        key_retention_period: Duration::from_millis(200),
        auto_rotation_enabled: false, // Manual control
        ..Default::default()
    };

    let manager = KeyManager::new(config).await.unwrap();
    let initial_stats = manager.get_stats().await;

    // Get server for old key
    let old_server = manager.get_server_by_id(initial_stats.active_key_id).await;
    assert!(old_server.is_some());

    // Rotate keys
    manager.rotate_keys().await.unwrap();
    let new_stats = manager.get_stats().await;

    // Old key should still be available for decryption
    let old_server_after_rotation = manager.get_server_by_id(initial_stats.active_key_id).await;
    assert!(old_server_after_rotation.is_some());

    // New key should also be available
    let new_server = manager.get_server_by_id(new_stats.active_key_id).await;
    assert!(new_server.is_some());

    // Active key should have changed
    assert_ne!(initial_stats.active_key_id, new_stats.active_key_id);
    assert_eq!(new_stats.total_keys, 2);
}

#[tokio::test]
async fn test_invalid_key_id_handling() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let stats = manager.get_stats().await;
    let invalid_key_id = stats.active_key_id.wrapping_add(100);

    // Should return None for invalid key ID
    let server = manager.get_server_by_id(invalid_key_id).await;
    assert!(server.is_none());
}

#[tokio::test]
async fn test_concurrent_key_operations() {
    let config = KeyManagerConfig::default();
    let manager = std::sync::Arc::new(KeyManager::new(config).await.unwrap());

    let mut handles = vec![];

    // Spawn multiple tasks that access keys concurrently
    for i in 0..10 {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            if i % 2 == 0 {
                // Half the tasks get the current server
                let _server = manager_clone.get_current_server().await.unwrap();
            } else {
                // Half get stats
                let _stats = manager_clone.get_stats().await;
            }
        });
        handles.push(handle);
    }

    // Wait for all tasks to complete
    for handle in handles {
        handle.await.unwrap();
    }

    // Manager should still be functional
    let final_stats = manager.get_stats().await;
    assert_eq!(final_stats.total_keys, 1);
}

#[tokio::test]
async fn test_automatic_rotation_scheduler() {
    let config = KeyManagerConfig {
        rotation_interval: Duration::from_millis(100),
        key_retention_period: Duration::from_millis(200),
        auto_rotation_enabled: true,
        ..Default::default()
    };

    let manager = std::sync::Arc::new(KeyManager::new(config).await.unwrap());
    let initial_stats = manager.get_stats().await;

    // Start the rotation scheduler
    let manager_clone = manager.clone();
    manager_clone.start_rotation_scheduler().await;

    // Wait for automatic rotation to occur
    tokio::time::sleep(Duration::from_millis(300)).await;

    let final_stats = manager.get_stats().await;

    // Key should have rotated automatically
    // Note: This test might be flaky depending on timing
    assert!(final_stats.active_key_id != initial_stats.active_key_id || final_stats.total_keys > 1);
}

#[tokio::test]
async fn test_config_serialization_format() {
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await.unwrap();

    let encoded_config = manager.get_encoded_config().await.unwrap();

    // Verify we have config data with 2-byte length prefix per RFC 9458
    assert!(!encoded_config.is_empty());
    assert!(encoded_config.len() > 12); // At least 2 bytes for length + some config data

    // Verify the length prefix is correct
    let length_prefix = u16::from_be_bytes([encoded_config[0], encoded_config[1]]);
    assert_eq!(length_prefix as usize, encoded_config.len() - 2);

    // Verify it contains reasonable OHTTP key configuration data
    assert!(encoded_config.len() < 1000); // Reasonable upper bound

    // The config should be the length-prefixed encoded configuration
    let config_data = &encoded_config[2..]; // Skip the length prefix
    assert!(!config_data.is_empty());
}

#[tokio::test]
async fn test_error_conditions() {
    // Test various error conditions

    // Invalid seed length
    let config = KeyManagerConfig::default();
    let short_seed = vec![0u8; 16];
    let result = KeyManager::new_with_seed(config.clone(), short_seed).await;
    assert!(result.is_err());

    // Test with empty cipher suites (if your implementation supports this validation)
    let invalid_config = KeyManagerConfig {
        cipher_suites: vec![], // Empty cipher suites
        ..Default::default()
    };

    // Should return an error for empty cipher suites
    let result = KeyManager::new(invalid_config).await;
    assert!(
        result.is_err(),
        "KeyManager should reject empty cipher suites"
    );
}
