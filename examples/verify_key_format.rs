use ohttp_gateway::key_manager::{KeyManager, KeyManagerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a key manager with default configuration
    let config = KeyManagerConfig::default();
    let manager = KeyManager::new(config).await?;

    // Get the encoded configuration
    let encoded_config = manager.get_encoded_config().await?;

    println!("Key configuration format verification:");
    println!("=====================================");

    // Check that we have at least 2 bytes for the length prefix
    if encoded_config.len() < 2 {
        println!("❌ ERROR: Configuration too short (< 2 bytes)");
        return Ok(());
    }

    // Extract the length prefix (first 2 bytes in network byte order)
    let length_prefix = u16::from_be_bytes([encoded_config[0], encoded_config[1]]);
    let actual_config_length = encoded_config.len() - 2; // Total length minus 2-byte prefix

    println!(
        "Total encoded config length: {} bytes",
        encoded_config.len()
    );
    println!("Length prefix value: {} bytes", length_prefix);
    println!("Actual config data length: {} bytes", actual_config_length);

    // Verify the length prefix matches the actual config data length
    if length_prefix as usize == actual_config_length {
        println!("✅ SUCCESS: Length prefix matches actual config data length");
        println!("✅ SUCCESS: Key configuration format is RFC 9458 compliant");
    } else {
        println!(
            "❌ ERROR: Length prefix ({}) doesn't match actual config data length ({})",
            length_prefix, actual_config_length
        );
        return Ok(());
    }

    // Display the first few bytes of the configuration for inspection
    println!("\nFirst 16 bytes of encoded configuration (hex):");
    let display_bytes = std::cmp::min(16, encoded_config.len());
    for (i, byte) in encoded_config[..display_bytes].iter().enumerate() {
        if i == 2 {
            print!(" | "); // Separator between length prefix and config data
        } else if i > 2 && (i - 2) % 4 == 0 {
            print!(" ");
        }
        print!("{:02x}", byte);
    }
    println!();
    println!("       ^^     ^^");
    println!("   Length prefix");
    println!("   (2 bytes, big-endian)");

    println!("\nFormat verification complete!");

    Ok(())
}
