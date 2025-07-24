use crate::{error::GatewayError, state::AppState};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bhttp::{Message, Mode};
use tracing::{debug, error, info, warn};

const OHTTP_REQUEST_CONTENT_TYPE: &str = "message/ohttp-req";
const OHTTP_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-res";

pub async fn handle_ohttp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let timer = state.metrics.request_duration.start_timer();
    state.metrics.requests_total.inc();

    // Extract key ID from the request if possible
    let key_id = extract_key_id_from_request(&body);

    let result = handle_ohttp_request_inner(state.clone(), headers, body, key_id).await;
    timer.stop_and_record();

    match result {
        Ok(response) => response,
        Err(e) => {
            error!("OHTTP request failed: {:?}", e);

            // Log metrics based on error type
            match &e {
                GatewayError::DecryptionError(_) => state.metrics.decryption_errors_total.inc(),
                GatewayError::EncryptionError(_) => state.metrics.encryption_errors_total.inc(),
                GatewayError::BackendError(_) => state.metrics.backend_errors_total.inc(),
                _ => {}
            }

            e.into_response()
        }
    }
}

async fn handle_ohttp_request_inner(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    key_id: Option<u8>,
) -> Result<Response, GatewayError> {
    // Validate request
    validate_ohttp_request(&headers, &body, &state)?;

    debug!(
        "Received OHTTP request with {} bytes, key_id: {:?}",
        body.len(),
        key_id
    );

    // Get the appropriate server based on key ID
    let server = if let Some(id) = key_id {
        // Try to get server for specific key ID
        match state.key_manager.get_server_by_id(id).await {
            Some(server) => {
                debug!("Using server for key ID: {}", id);
                server
            }
            None => {
                warn!("Unknown key ID: {}, falling back to current server", id);
                state
                    .key_manager
                    .get_current_server()
                    .await
                    .map_err(|e| GatewayError::ConfigurationError(e.to_string()))?
            }
        }
    } else {
        // Use current active server
        state
            .key_manager
            .get_current_server()
            .await
            .map_err(|e| GatewayError::ConfigurationError(e.to_string()))?
    };

    // Decrypt the OHTTP request
    let (bhttp_request, server_response) = server.decapsulate(&body).map_err(|e| {
        error!("Failed to decapsulate OHTTP request: {e}");
        GatewayError::DecryptionError(format!("Failed to decapsulate: {e}"))
    })?;

    debug!("Request: {:#?}", bhttp_request);

    debug!(
        "Successfully decapsulated request, {} bytes",
        bhttp_request.len()
    );

    // Parse binary HTTP message
    let message = parse_bhttp_message(&bhttp_request)?;

    // Validate and potentially transform the request
    let message = validate_and_transform_request(message, &state)?;

    // Forward request to backend
    let backend_response = forward_to_backend(&state, message).await?;

    // Convert response to binary HTTP format
    let bhttp_response = convert_to_binary_http(backend_response).await?;

    // Encrypt response back to client
    let encrypted_response = server_response.encapsulate(&bhttp_response).map_err(|e| {
        GatewayError::EncryptionError(format!("Failed to encapsulate response: {e}"))
    })?;

    state.metrics.successful_requests_total.inc();
    info!("Successfully processed OHTTP request");

    // Build response with appropriate headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, OHTTP_RESPONSE_CONTENT_TYPE)
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .body(Body::from(encrypted_response))
        .map_err(|e| GatewayError::InternalError(format!("Response build error: {e}")))
}

/// Extract key ID from OHTTP request (first byte after version)
fn extract_key_id_from_request(body: &[u8]) -> Option<u8> {
    // OHTTP request format: version(1) + key_id(1) + kem_id(2) + kdf_id(2) + aead_id(2) + enc + ciphertext
    if body.len() > 1 { Some(body[1]) } else { None }
}

/// Validate the incoming OHTTP request
fn validate_ohttp_request(
    headers: &HeaderMap,
    body: &Bytes,
    state: &AppState,
) -> Result<(), GatewayError> {
    // Check content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| GatewayError::InvalidRequest("Missing content-type header".to_string()))?;

    if content_type != OHTTP_REQUEST_CONTENT_TYPE {
        return Err(GatewayError::InvalidRequest(format!(
            "Invalid content-type: expected '{OHTTP_REQUEST_CONTENT_TYPE}', got '{content_type}'"
        )));
    }

    // Check body size
    if body.is_empty() {
        return Err(GatewayError::InvalidRequest(
            "Empty request body".to_string(),
        ));
    }

    if body.len() > state.config.max_body_size {
        return Err(GatewayError::RequestTooLarge(format!(
            "Request body too large: {} bytes (max: {})",
            body.len(),
            state.config.max_body_size
        )));
    }

    // Minimum OHTTP request size check
    if body.len() < 10 {
        return Err(GatewayError::InvalidRequest(
            "Request too small to be valid OHTTP".to_string(),
        ));
    }

    Ok(())
}

/// Parse binary HTTP message with error handling
fn parse_bhttp_message(data: &[u8]) -> Result<Message, GatewayError> {
    let mut cursor = std::io::Cursor::new(data);
    debug!("Cursor: std::io::Cursor::new(data): {:?}", cursor);

    Message::read_bhttp(&mut cursor)
        .map_err(|e| GatewayError::InvalidRequest(format!("Failed to parse binary HTTP: {e}")))
}

/// Validate and transform the request based on security policies
fn validate_and_transform_request(
    message: Message,
    state: &AppState,
) -> Result<Message, GatewayError> {
    let control = message.control();

    // Extract host from authority or Host header
    let host = control
        .authority()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .or_else(|| {
            message.header().fields().iter().find_map(|field| {
                if field.name().eq_ignore_ascii_case(b"host") {
                    Some(String::from_utf8_lossy(field.value()).into_owned())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| GatewayError::InvalidRequest("Missing host/authority".to_string()))?;

    // Extract and clean the path
    let raw_path = control.path().unwrap_or(b"/");
    let path_str = String::from_utf8_lossy(raw_path);

    // Clean up the path - remove any absolute URL components
    let clean_path = if path_str.starts_with("http://") || path_str.starts_with("https://") {
        // Extract just the path from absolute URL
        if let Some(idx) = path_str
            .find('/')
            .and_then(|i| path_str[i + 2..].find('/').map(|j| i + 2 + j))
        {
            path_str[idx..].as_bytes()
        } else {
            b"/"
        }
    } else if path_str.contains(':') && !path_str.starts_with('/') {
        // Path might contain host:port, clean it
        b"/"
    } else {
        raw_path
    };

    debug!(
        "Request details - host: {}, original_path: {}, clean_path: {}",
        host,
        path_str,
        String::from_utf8_lossy(clean_path)
    );

    // Check if origin is allowed
    if !state.config.is_origin_allowed(&host) {
        warn!("Blocked request to forbidden origin: {host}");
        return Err(GatewayError::InvalidRequest(format!(
            "Target origin not allowed: {host}"
        )));
    }

    // Apply any configured rewrites
    if let Some(rewrite) = state.config.get_rewrite(&host) {
        debug!(
            "Applying rewrite for host {}: {} -> {}",
            host, rewrite.scheme, rewrite.host
        );

        // Clone the message to modify it
        let mut new_message = Message::request(
            Vec::from(control.method().unwrap_or(b"GET")), // method
            Vec::from(rewrite.scheme.as_bytes()),          // scheme
            Vec::from(rewrite.host.as_bytes()),            // authority
            Vec::from(clean_path),                         // path
        );

        // Copy all headers except Host and Authority
        for field in message.header().fields() {
            let name = field.name();
            if !name.eq_ignore_ascii_case(b"host") && !name.eq_ignore_ascii_case(b"authority") {
                new_message.put_header(name, field.value());
            }
        }

        // Add the new Host header
        new_message.put_header(b"host", rewrite.host.as_bytes());

        // Copy body content
        if !message.content().is_empty() {
            new_message.write_content(message.content());
        }

        return Ok(new_message);
    }

    Ok(message)
}

async fn forward_to_backend(
    state: &AppState,
    bhttp_message: Message,
) -> Result<reqwest::Response, GatewayError> {
    let control = bhttp_message.control();
    let method = control.method().unwrap_or(b"GET");
    let path = control
        .path()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "/".to_string());

    // Extract host for URL construction
    let host = control
        .authority()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .or_else(|| {
            bhttp_message.header().fields().iter().find_map(|field| {
                if field.name().eq_ignore_ascii_case(b"host") {
                    Some(String::from_utf8_lossy(field.value()).into_owned())
                } else {
                    None
                }
            })
        });

    // Build the backend URI
    let uri = if let Some(host) = host {
        // Extract scheme, handling various formats
        let scheme = control
            .scheme()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_else(|| "http".to_string());
        format!("{scheme}://{host}{path}")
    } else {
        build_backend_uri(&state.config.backend_url, &path)?
    };

    info!(
        "Forwarding {} request to {}",
        String::from_utf8_lossy(method),
        uri
    );

    let reqwest_method = convert_method_to_reqwest(method);
    let mut request_builder = state.http_client.request(reqwest_method, &uri);

    // Add headers from the binary HTTP message
    for field in bhttp_message.header().fields() {
        let name = String::from_utf8_lossy(field.name());
        let value = String::from_utf8_lossy(field.value());

        // Skip headers that should not be forwarded
        if should_forward_header(&name) {
            request_builder = request_builder.header(name.as_ref(), value.as_ref());
        }
    }

    // Add body if present
    let content = bhttp_message.content();
    if !content.is_empty() {
        request_builder = request_builder.body(content.to_vec());
    }

    // Send request with timeout
    let response = request_builder.send().await.map_err(|e| {
        error!("Backend request failed: {e}");
        GatewayError::BackendError(format!("Backend request failed: {e}"))
    })?;

    // Check for backend errors
    if response.status().is_server_error() {
        return Err(GatewayError::BackendError(format!(
            "Backend returned error: {}",
            response.status()
        )));
    }

    Ok(response)
}

fn convert_method_to_reqwest(method: &[u8]) -> reqwest::Method {
    match method {
        b"GET" => reqwest::Method::GET,
        b"POST" => reqwest::Method::POST,
        b"PUT" => reqwest::Method::PUT,
        b"DELETE" => reqwest::Method::DELETE,
        b"HEAD" => reqwest::Method::HEAD,
        b"OPTIONS" => reqwest::Method::OPTIONS,
        b"PATCH" => reqwest::Method::PATCH,
        b"TRACE" => reqwest::Method::TRACE,
        _ => reqwest::Method::GET,
    }
}

fn build_backend_uri(backend_url: &str, path: &str) -> Result<String, GatewayError> {
    let base_url = backend_url.trim_end_matches('/');
    let clean_path = if path.starts_with('/') {
        path
    } else {
        &format!("/{path}")
    };

    // Validate path to prevent SSRF attacks
    if clean_path.contains("..") || clean_path.contains("//") {
        return Err(GatewayError::InvalidRequest(
            "Invalid path detected".to_string(),
        ));
    }

    // Additional validation for suspicious patterns
    if clean_path.contains('\0') || clean_path.contains('\r') || clean_path.contains('\n') {
        return Err(GatewayError::InvalidRequest(
            "Invalid characters in path".to_string(),
        ));
    }

    // Build the final URI with explicit formatting
    let final_uri = format!("{base_url}{clean_path}");
    debug!("build_backend_uri: final_uri = '{}'", final_uri);

    Ok(final_uri)
}

fn should_forward_header(name: &str) -> bool {
    const SKIP_HEADERS: &[&str] = &[
        "host",
        "connection",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailers",
        "transfer-encoding",
        "keep-alive",
        "http2-settings",
        "upgrade-insecure-requests",
    ];

    !SKIP_HEADERS.contains(&name.to_lowercase().as_str())
}

async fn convert_to_binary_http(response: reqwest::Response) -> Result<Vec<u8>, GatewayError> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .await
        .map_err(|e| GatewayError::BackendError(format!("Failed to read response body: {e}")))?;

    // Create a bhttp response message
    let mut message = Message::response(
        bhttp::StatusCode::try_from(status.as_u16())
            .map_err(|_| GatewayError::InternalError("Invalid status code".to_string()))?,
    );

    // Add headers
    for (name, value) in headers.iter() {
        if should_forward_header(name.as_str()) {
            message.put_header(name.as_str().as_bytes(), value.as_bytes());
        }
    }

    // Add body
    if !body.is_empty() {
        message.write_content(&body);
    }

    // Serialize to binary HTTP using KnownLength mode for compatibility
    let mut output = Vec::new();
    message
        .write_bhttp(Mode::KnownLength, &mut output)
        .map_err(|e| GatewayError::InternalError(format!("Failed to write binary HTTP: {e}")))?;

    debug!("Created BHTTP response of {} bytes", output.len());

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_key_id() {
        let body = vec![0x00, 0x7F, 0x00, 0x01]; // version, key_id, kem_id...
        assert_eq!(extract_key_id_from_request(&body), Some(0x7F));

        let empty = vec![];
        assert_eq!(extract_key_id_from_request(&empty), None);
    }

    #[test]
    fn test_should_forward_header() {
        assert!(should_forward_header("content-type"));
        assert!(should_forward_header("authorization"));
        assert!(!should_forward_header("connection"));
        assert!(!should_forward_header("Host"));
    }

    #[test]
    fn test_build_backend_uri() {
        assert_eq!(
            build_backend_uri("https://backend.com", "/api/test").unwrap(),
            "https://backend.com/api/test"
        );

        assert_eq!(
            build_backend_uri("https://backend.com/", "/api/test").unwrap(),
            "https://backend.com/api/test"
        );

        assert!(build_backend_uri("https://backend.com", "/../etc/passwd").is_err());
        assert!(build_backend_uri("https://backend.com", "//evil.com").is_err());
    }
}
