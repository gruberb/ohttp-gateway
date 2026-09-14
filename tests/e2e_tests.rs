use axum::{Router, body::Bytes, http::StatusCode};
use bhttp::{Message, Mode};
use ohttp::{
    ClientRequest, KeyConfig, SymmetricSuite,
    hpke::{Aead, Kdf, Kem},
};
use ohttp_gateway::{AppConfig, AppState};
use std::net::SocketAddr;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

/// Starts a mock backend that returns `response_body` for any request.
async fn start_mock_backend(response_body: &'static [u8]) -> SocketAddr {
    let app = Router::new().fallback(move || async move { response_body.to_vec() });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Starts a mock backend that echoes the request body back.
async fn start_echo_backend() -> SocketAddr {
    let app = Router::new().fallback(|body: Bytes| async move { body });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Starts a mock backend that always returns 500.
async fn start_error_backend() -> SocketAddr {
    let app =
        Router::new().fallback(|| async { (StatusCode::INTERNAL_SERVER_ERROR, "backend error") });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

/// Creates an `AppState` whose backend points at `backend_addr` and serves the
/// gateway routes on a random port. Returns the gateway address.
async fn start_gateway(backend_addr: SocketAddr) -> (SocketAddr, AppState) {
    start_gateway_with_config(AppConfig {
        backend_url: format!("http://{}", backend_addr),
        debug_mode: true,
        key_rotation_enabled: false,
        ..Default::default()
    })
    .await
}

/// Starts a gateway with a specific config on a random port.
async fn start_gateway_with_config(config: AppConfig) -> (SocketAddr, AppState) {
    let state = AppState::new(config).await.unwrap();

    let app = ohttp_gateway::handlers::routes().with_state(state.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, state)
}

/// Fetches the gateway's key config bytes from /ohttp-configs, strips the
/// 2-byte length prefix, and returns the raw KeyConfig encoding.
async fn fetch_config(gateway_addr: SocketAddr) -> Vec<u8> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/ohttp-configs", gateway_addr))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = resp.bytes().await.unwrap();
    // Strip 2-byte length prefix
    bytes[2..].to_vec()
}

/// Encrypt a BHTTP payload using the gateway's public key config.
/// Returns (encrypted_request, client_response) where client_response is used
/// to decrypt the server's reply.
fn encrypt_request(config_bytes: &[u8], bhttp_bytes: &[u8]) -> (Vec<u8>, ohttp::ClientResponse) {
    let mut config = KeyConfig::decode(config_bytes).unwrap();
    let client_request = ClientRequest::from_config(&mut config).unwrap();
    let (enc_request, client_response) = client_request.encapsulate(bhttp_bytes).unwrap();
    (enc_request, client_response)
}

/// Build a serialized BHTTP GET request.
fn make_bhttp_get(authority: &str, path: &str) -> Vec<u8> {
    let msg = Message::request(
        b"GET".to_vec(),
        b"http".to_vec(),
        authority.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    let mut buf = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut buf).unwrap();
    buf
}

/// Build a serialized BHTTP POST request with a body.
fn make_bhttp_post(authority: &str, path: &str, body: &[u8]) -> Vec<u8> {
    let mut msg = Message::request(
        b"POST".to_vec(),
        b"http".to_vec(),
        authority.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    msg.write_content(body);
    let mut buf = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut buf).unwrap();
    buf
}

/// Send an encrypted OHTTP request to the gateway and return the raw response.
async fn send_ohttp_request(gateway_addr: SocketAddr, encrypted_body: &[u8]) -> reqwest::Response {
    let client = reqwest::Client::new();
    client
        .post(format!("http://{}/gateway", gateway_addr))
        .header("content-type", "message/ohttp-req")
        .body(encrypted_body.to_vec())
        .send()
        .await
        .unwrap()
}

/// Extract the response body from a decrypted BHTTP response message.
fn extract_response_body(bhttp_bytes: &[u8]) -> (u16, Vec<u8>) {
    let mut cursor = std::io::Cursor::new(bhttp_bytes);
    let msg = Message::read_bhttp(&mut cursor).unwrap();
    let status = msg.control().status().map(u16::from).unwrap_or(0);
    (status, msg.content().to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_e2e_happy_path_get() {
    let backend_body: &[u8] = b"Hello from backend!";
    let backend_addr = start_mock_backend(backend_body).await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    // 1. Fetch key config
    let config_bytes = fetch_config(gateway_addr).await;

    // 2. Build BHTTP GET aimed at the backend
    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/test");

    // 3. Encrypt
    let (enc_req, client_resp) = encrypt_request(&config_bytes, &bhttp);

    // 4. Send to gateway
    let resp = send_ohttp_request(gateway_addr, &enc_req).await;
    assert_eq!(resp.status(), 200);
    let enc_response = resp.bytes().await.unwrap();

    // 5. Decrypt
    let decrypted = client_resp.decapsulate(&enc_response).unwrap();
    let (status, body) = extract_response_body(&decrypted);

    assert_eq!(status, 200);
    assert_eq!(body, backend_body);
}

#[tokio::test]
async fn test_e2e_happy_path_post() {
    let backend_addr = start_echo_backend().await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    let config_bytes = fetch_config(gateway_addr).await;

    let request_body = b"echo me please";
    let bhttp = make_bhttp_post(&backend_addr.to_string(), "/echo", request_body);
    let (enc_req, client_resp) = encrypt_request(&config_bytes, &bhttp);

    let resp = send_ohttp_request(gateway_addr, &enc_req).await;
    assert_eq!(resp.status(), 200);
    let enc_response = resp.bytes().await.unwrap();

    let decrypted = client_resp.decapsulate(&enc_response).unwrap();
    let (status, body) = extract_response_body(&decrypted);

    assert_eq!(status, 200);
    assert_eq!(body, request_body);
}

#[tokio::test]
async fn test_e2e_wrong_key_rejected() {
    let backend_addr = start_mock_backend(b"ok").await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    // Generate an independent key config (not from the gateway)
    let mut wrong_config = KeyConfig::new(
        0x42,
        Kem::X25519Sha256,
        vec![SymmetricSuite::new(Kdf::HkdfSha256, Aead::Aes128Gcm)],
    )
    .unwrap();

    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/test");

    let client_request = ClientRequest::from_config(&mut wrong_config).unwrap();
    let (enc_req, _) = client_request.encapsulate(&bhttp).unwrap();

    let resp = send_ohttp_request(gateway_addr, &enc_req).await;
    // Gateway should reject with 400 (decryption error)
    assert_eq!(resp.status(), 400);

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("decryption_error") || body.contains("decapsulate"),
        "Expected decryption error, got: {body}"
    );
}

#[tokio::test]
async fn test_e2e_key_rotation_old_key_works() {
    let backend_body: &[u8] = b"rotation test ok";
    let backend_addr = start_mock_backend(backend_body).await;
    let (gateway_addr, state) = start_gateway(backend_addr).await;

    // Fetch config BEFORE rotation
    let old_config_bytes = fetch_config(gateway_addr).await;

    // Encrypt with the old config
    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/test");
    let (enc_req, client_resp) = encrypt_request(&old_config_bytes, &bhttp);

    // Rotate keys
    state.key_manager.rotate_keys().await.unwrap();

    // Send the request encrypted with the OLD key — should still work
    let resp = send_ohttp_request(gateway_addr, &enc_req).await;
    assert_eq!(resp.status(), 200);

    let enc_response = resp.bytes().await.unwrap();
    let decrypted = client_resp.decapsulate(&enc_response).unwrap();
    let (status, body) = extract_response_body(&decrypted);

    assert_eq!(status, 200);
    assert_eq!(body, backend_body);
}

#[tokio::test]
async fn test_e2e_invalid_content_type() {
    let backend_addr = start_mock_backend(b"ok").await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/gateway", gateway_addr))
        .header("content-type", "application/json")
        .body(vec![0u8; 20])
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("invalid_request") || body.contains("content-type"),
        "Expected content-type error, got: {body}"
    );
}

#[tokio::test]
async fn test_e2e_empty_body() {
    let backend_addr = start_mock_backend(b"ok").await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/gateway", gateway_addr))
        .header("content-type", "message/ohttp-req")
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("invalid_request") || body.contains("Empty"),
        "Expected empty body error, got: {body}"
    );
}

#[tokio::test]
async fn test_e2e_backend_error() {
    let backend_addr = start_error_backend().await;
    let (gateway_addr, _state) = start_gateway(backend_addr).await;

    let config_bytes = fetch_config(gateway_addr).await;
    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/fail");
    let (enc_req, _client_resp) = encrypt_request(&config_bytes, &bhttp);

    let resp = send_ohttp_request(gateway_addr, &enc_req).await;
    assert_eq!(resp.status(), 502);

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("backend_error"),
        "Expected backend error, got: {body}"
    );
}

#[tokio::test]
async fn test_e2e_restart_loses_ephemeral_keys() {
    let backend_addr = start_mock_backend(b"ok").await;

    // Start first gateway (no seed = ephemeral keys)
    let (gateway_addr1, _state1) = start_gateway(backend_addr).await;

    // Fetch config and encrypt a request with the first gateway's keys
    let config_bytes = fetch_config(gateway_addr1).await;
    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/test");
    let (enc_req, _client_resp) = encrypt_request(&config_bytes, &bhttp);

    // "Restart": create a new gateway with new random keys
    let (gateway_addr2, _state2) = start_gateway(backend_addr).await;

    // Send the old encrypted request to the new gateway — should fail
    let resp = send_ohttp_request(gateway_addr2, &enc_req).await;
    assert_eq!(
        resp.status(),
        400,
        "Expected 400 decryption error after restart with ephemeral keys"
    );
}

#[tokio::test]
async fn test_e2e_restart_preserves_seeded_keys() {
    let backend_body: &[u8] = b"seeded restart ok";
    let backend_addr = start_mock_backend(backend_body).await;
    let seed = "ab".repeat(32); // 64 hex chars = 32 bytes

    // Start first gateway with seed
    let config1 = AppConfig {
        backend_url: format!("http://{}", backend_addr),
        debug_mode: true,
        key_rotation_enabled: false,
        seed_secret_key: Some(seed.clone()),
        ..Default::default()
    };
    let (gateway_addr1, _state1) = start_gateway_with_config(config1).await;

    // Fetch config and encrypt a request
    let config_bytes = fetch_config(gateway_addr1).await;
    let bhttp = make_bhttp_get(&backend_addr.to_string(), "/test");
    let (enc_req, client_resp) = encrypt_request(&config_bytes, &bhttp);

    // "Restart": create a new gateway with the SAME seed
    let config2 = AppConfig {
        backend_url: format!("http://{}", backend_addr),
        debug_mode: true,
        key_rotation_enabled: false,
        seed_secret_key: Some(seed),
        ..Default::default()
    };
    let (gateway_addr2, _state2) = start_gateway_with_config(config2).await;

    // Send the old encrypted request to the new gateway — should succeed
    let resp = send_ohttp_request(gateway_addr2, &enc_req).await;
    assert_eq!(
        resp.status(),
        200,
        "Expected 200 success after restart with seeded keys"
    );

    let enc_response = resp.bytes().await.unwrap();
    let decrypted = client_resp.decapsulate(&enc_response).unwrap();
    let (status, body) = extract_response_body(&decrypted);

    assert_eq!(status, 200);
    assert_eq!(body, backend_body);
}
