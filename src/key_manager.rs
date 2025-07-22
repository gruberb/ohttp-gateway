use chrono::{DateTime, Utc};
use ohttp::{
    KeyConfig, Server as OhttpServer, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{error, info};

/// Represents a key with its metadata
#[derive(Clone, Debug)]
pub struct KeyInfo {
    pub id: u8,
    pub config: KeyConfig,
    pub server: OhttpServer,
    pub expires_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Configuration for key management
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyManagerConfig {
    /// How often to rotate keys (default: 30 days)
    pub rotation_interval: Duration,
    /// How long to keep old keys for decryption (default: 7 days)
    pub key_retention_period: Duration,
    /// Whether to enable automatic rotation
    pub auto_rotation_enabled: bool,
    /// Supported cipher suites
    pub cipher_suites: Vec<CipherSuiteConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CipherSuiteConfig {
    pub kem: String,
    pub kdf: String,
    pub aead: String,
}

impl Default for KeyManagerConfig {
    fn default() -> Self {
        Self {
            rotation_interval: Duration::from_secs(30 * 24 * 60 * 60), // 30 days
            key_retention_period: Duration::from_secs(7 * 24 * 60 * 60), // 7 days
            auto_rotation_enabled: true,
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
        }
    }
}

pub struct KeyManager {
    /// All keys indexed by ID
    keys: Arc<RwLock<HashMap<u8, KeyInfo>>>,
    /// Current active key ID
    active_key_id: Arc<RwLock<u8>>,
    /// Configuration
    config: KeyManagerConfig,
    /// Key ID counter (wraps around after 255)
    next_key_id: Arc<RwLock<u8>>,
    /// Seed for deterministic key generation (optional)
    seed: Option<Vec<u8>>,
}

impl KeyManager {
    pub async fn new(config: KeyManagerConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            active_key_id: Arc::new(RwLock::new(0)),
            config,
            next_key_id: Arc::new(RwLock::new(1)),
            seed: None,
        };

        // Generate initial key
        let initial_key = manager.generate_new_key().await?;
        {
            let mut keys = manager.keys.write().await;
            let mut active_id = manager.active_key_id.write().await;

            keys.insert(initial_key.id, initial_key.clone());
            *active_id = initial_key.id;
        }

        info!("KeyManager initialized with key ID: {}", initial_key.id);
        Ok(manager)
    }

    /// Create a key manager with a seed for deterministic key generation
    pub async fn new_with_seed(
        config: KeyManagerConfig,
        seed: Vec<u8>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        if seed.len() < 32 {
            return Err("Seed must be at least 32 bytes".into());
        }

        let manager = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            active_key_id: Arc::new(RwLock::new(0)),
            config,
            next_key_id: Arc::new(RwLock::new(1)),
            seed: Some(seed),
        };

        // Generate initial key (will now use the seed)
        let initial_key = manager.generate_new_key().await?;
        {
            let mut keys = manager.keys.write().await;
            let mut active_id = manager.active_key_id.write().await;

            keys.insert(initial_key.id, initial_key.clone());
            *active_id = initial_key.id;
        }

        info!("KeyManager initialized with key ID: {}", initial_key.id);
        Ok(manager)
    }

    /// Generate a new key configuration
    async fn generate_new_key(&self) -> Result<KeyInfo, Box<dyn std::error::Error>> {
        let key_id = {
            let mut next_id = self.next_key_id.write().await;
            let id = *next_id;
            *next_id = next_id.wrapping_add(1);
            id
        };

        // Parse cipher suites from config
        let mut symmetric_suites = Vec::new();
        for suite in &self.config.cipher_suites {
            let kdf = match suite.kdf.as_str() {
                "HKDF_SHA256" => Kdf::HkdfSha256,
                "HKDF_SHA384" => Kdf::HkdfSha384,
                "HKDF_SHA512" => Kdf::HkdfSha512,
                _ => Kdf::HkdfSha256,
            };

            let aead = match suite.aead.as_str() {
                "AES_128_GCM" => Aead::Aes128Gcm,
                "AES_256_GCM" => Aead::Aes256Gcm,
                "CHACHA20_POLY1305" => Aead::ChaCha20Poly1305,
                _ => Aead::Aes128Gcm,
            };

            symmetric_suites.push(SymmetricSuite::new(kdf, aead));
        }

        // Validate that we have at least one cipher suite
        if symmetric_suites.is_empty() {
            return Err("No valid cipher suites configured".into());
        }

        // Determine KEM based on config - only X25519 is supported by ohttp crate
        let kem = Kem::X25519Sha256;

        // Generate key config
        let key_config = if let Some(seed) = &self.seed {
            // Deterministic generation using seed + key_id
            let mut key_seed = seed.clone();
            key_seed.push(key_id);

            KeyConfig::derive(key_id, kem, symmetric_suites, &key_seed)?
        } else {
            KeyConfig::new(key_id, kem, symmetric_suites)?
        };

        let server = OhttpServer::new(key_config.clone())?;
        let now = Utc::now();

        Ok(KeyInfo {
            id: key_id,
            config: key_config,
            server,
            expires_at: now + chrono::Duration::from_std(self.config.rotation_interval)?,
            is_active: true,
        })
    }

    /// Get the current active server for decryption
    pub async fn get_current_server(&self) -> Result<OhttpServer, Box<dyn std::error::Error>> {
        let keys = self.keys.read().await;
        let active_id = self.active_key_id.read().await;

        keys.get(&*active_id)
            .map(|info| info.server.clone())
            .ok_or_else(|| "No active key found".into())
    }

    /// Get a server by key ID (for handling requests with specific key IDs)
    pub async fn get_server_by_id(&self, key_id: u8) -> Option<OhttpServer> {
        let keys = self.keys.read().await;
        keys.get(&key_id).map(|info| info.server.clone())
    }

    /// Get encoded config for backward compatibility
    pub async fn get_encoded_config(&self) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let keys = self.keys.read().await;
        let active_id = self.active_key_id.read().await;
        let cfg_bytes = keys
            .get(&*active_id)
            .ok_or("no active key")?
            .config
            .encode()?;

        let mut out = Vec::with_capacity(cfg_bytes.len() + 2);
        out.extend_from_slice(&(cfg_bytes.len() as u16).to_be_bytes()); // 2-byte length
        out.extend_from_slice(&cfg_bytes);
        Ok(out)
    }

    /// Rotate keys by generating a new key and marking old ones for expiration
    pub async fn rotate_keys(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting key rotation");

        // Generate new key
        let new_key = self.generate_new_key().await?;
        let new_key_id = new_key.id;

        // Update key store
        {
            let mut keys = self.keys.write().await;
            let mut active_id = self.active_key_id.write().await;
            let now = Utc::now();

            // Mark current active key for future expiration
            if let Some(current_key) = keys.get_mut(&*active_id) {
                current_key.is_active = false;
                // Keep it around for the retention period
                current_key.expires_at =
                    now + chrono::Duration::from_std(self.config.key_retention_period)?;
            }

            // Add new key
            keys.insert(new_key_id, new_key);

            // Update active key ID
            *active_id = new_key_id;

            // Clean up expired keys
            keys.retain(|_, info| info.expires_at > now);

            info!(
                "Key rotation completed. New active key ID: {}, total keys: {}",
                new_key_id,
                keys.len()
            );
        }

        Ok(())
    }

    /// Check if rotation is needed
    pub async fn should_rotate(&self) -> bool {
        let keys = self.keys.read().await;
        let active_id = self.active_key_id.read().await;

        if let Some(active_key) = keys.get(&*active_id) {
            let time_until_expiry = active_key.expires_at.signed_duration_since(Utc::now());

            // Rotate if less than 10% of the rotation interval remains
            let threshold = chrono::Duration::from_std(self.config.rotation_interval / 10)
                .unwrap_or_else(|_| chrono::Duration::days(3));

            time_until_expiry < threshold
        } else {
            true // No active key, definitely need to rotate
        }
    }

    /// Start automatic key rotation scheduler
    pub async fn start_rotation_scheduler(self: Arc<Self>) {
        if !self.config.auto_rotation_enabled {
            info!("Automatic key rotation is disabled");
            return;
        }

        let manager = self;
        tokio::spawn(async move {
            // Use the configured rotation interval for the scheduler
            let mut interval = tokio::time::interval(manager.config.rotation_interval);

            loop {
                interval.tick().await;

                if manager.should_rotate().await {
                    if let Err(e) = manager.rotate_keys().await {
                        error!("Key rotation failed: {}", e);
                    }
                }

                // Also clean up expired keys
                manager.cleanup_expired_keys().await;
            }
        });
    }

    /// Clean up expired keys
    async fn cleanup_expired_keys(&self) {
        let mut keys = self.keys.write().await;
        let now = Utc::now();
        let before_count = keys.len();

        keys.retain(|id, info| {
            if info.expires_at <= now {
                info!("Removing expired key ID: {}", id);
                false
            } else {
                true
            }
        });

        let removed = before_count - keys.len();
        if removed > 0 {
            info!("Cleaned up {} expired keys", removed);
        }
    }

    /// Get key manager statistics
    pub async fn get_stats(&self) -> KeyManagerStats {
        let keys = self.keys.read().await;
        let active_id = self.active_key_id.read().await;
        let now = Utc::now();

        let active_keys = keys.values().filter(|k| k.is_active).count();
        let total_keys = keys.len();
        let expired_keys = keys.values().filter(|k| k.expires_at <= now).count();

        KeyManagerStats {
            active_key_id: *active_id,
            total_keys,
            active_keys,
            expired_keys,
            rotation_interval: self.config.rotation_interval,
            auto_rotation_enabled: self.config.auto_rotation_enabled,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct KeyManagerStats {
    pub active_key_id: u8,
    pub total_keys: usize,
    pub active_keys: usize,
    pub expired_keys: usize,
    pub rotation_interval: Duration,
    pub auto_rotation_enabled: bool,
}

// Ensure thread safety
unsafe impl Send for KeyManager {}
unsafe impl Sync for KeyManager {}
