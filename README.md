# OHTTP Gateway

An RFC 9458 compliant Oblivious HTTP gateway implementation in Rust.

## Overview

This gateway implements the Oblivious HTTP protocol as defined in [RFC 9458](https://datatracker.ietf.org/doc/rfc9458/), providing a privacy-preserving HTTP proxy that prevents servers from linking requests to individual clients. The gateway acts as the decryption endpoint in the OHTTP architecture, receiving encrypted requests from relays and forwarding them to target servers.

OHTTP enables clients to make HTTP requests without revealing their identity to the target server by routing requests through a trusted relay that forwards encrypted messages to this gateway. The gateway decrypts the requests using HPKE (Hybrid Public Key Encryption), forwards them to the target server, and returns encrypted responses back through the relay.

## Architecture

Client -> Relay -> Gateway -> Target Server
             |        |
             |        v
             |    [Decrypt Request]
             |    [Forward to Target]
             |    [Encrypt Response]
             |        |
             <--------+


This implementation serves as the Gateway component, handling:
- HPKE-encrypted request decapsulation
- Request validation and origin policy enforcement
- Target server communication
- Response encryption and encapsulation
- Key management and rotation

## Features

- **RFC 9458 Compliance**: Full implementation of the OHTTP specification
- **HPKE Encryption**: Uses the `ohttp` crate with HPKE for secure request/response handling
- **Automatic Key Rotation**: Configurable key rotation with graceful key transitions
- **Security Controls**: Origin allowlists, request validation, and rate limiting
- **Target Rewrites**: Configurable request rewriting for backend routing
- **Observability**: Prometheus metrics, structured logging, and health checks
- **Production Ready**: Docker support, graceful shutdown, and comprehensive error handling

## Configuration

The gateway is configured via environment variables:

### Basic Configuration
```bash
LISTEN_ADDR=0.0.0.0:8080                    # Server bind address
BACKEND_URL=http://localhost:8080            # Default backend URL
REQUEST_TIMEOUT=30                           # Request timeout in seconds
MAX_BODY_SIZE=10485760                       # Maximum request body size (10MB)
```

### Key Management
```bash
KEY_ROTATION_INTERVAL=2592000                # Key rotation interval in seconds (30 days)
KEY_RETENTION_PERIOD=604800                  # Key retention period in seconds (7 days)
KEY_ROTATION_ENABLED=true                    # Enable automatic key rotation
SEED_SECRET_KEY=hex_encoded_32_byte_seed     # Optional deterministic key generation
```

### Security
```bash
ALLOWED_TARGET_ORIGINS=example.com,api.example.com  # Comma-separated allowed origins
TARGET_REWRITES='{"old.com":{"scheme":"https","host":"new.com"}}'  # JSON target rewrites
RATE_LIMIT_RPS=100                           # Requests per second limit
RATE_LIMIT_BURST=200                         # Burst size for rate limiting
RATE_LIMIT_BY_IP=true                        # Rate limit by client IP
```

### Operational
```bash
METRICS_ENABLED=true                         # Enable Prometheus metrics
GATEWAY_DEBUG=false                          # Enable debug mode
LOG_FORMAT=json                              # Log format: json or default
LOG_LEVEL=info                               # Log level: debug, info, warn, error
```

## Quick Start

### Using Docker
```bash
# Build the image
docker build -t ohttp-gateway .

# Run with basic configuration
docker run -p 8080:8080 \
  -e BACKEND_URL=https://httpbin.org \
  -e ALLOWED_TARGET_ORIGINS=httpbin.org \
  ohttp-gateway
```

### From Source
```bash
cargo build --release

# Run with environment configuration
export BACKEND_URL=https://httpbin.org
export ALLOWED_TARGET_ORIGINS=httpbin.org
./target/release/ohttp-gateway
```

## API Endpoints

### Gateway Endpoint

- `POST /gateway` - Main OHTTP request handler
  - Accepts `message/ohttp-req` content type
  - Returns `message/ohttp-res` content type

### Key Configuration

- `GET /ohttp-keys` - Retrieve current key configuration
  - Returns `application/ohttp-keys` content type
  - Used by clients to obtain encryption keys

### Health and Monitoring
- `GET /health` - Basic health check
- `GET /health/keys` - Key management health check
- `GET /metrics` - Prometheus metrics

## Client Integration

Clients need the key configuration to encrypt requests:

```bash
# Fetch key configuration
curl -H "Accept: application/ohttp-keys" https://gateway:8080/ohttp-keys

# Send OHTTP request (encrypted)
curl -X POST \
  -H "Content-Type: message/ohttp-req" \
  --data-binary @encrypted_request.bin \
  https://gateway:8080/gateway
```

Security Considerations

### Origin Control
Configure `ALLOWED_TARGET_ORIGINS` to restrict which domains the gateway can reach. Without this, the gateway may be used to proxy requests to unintended targets.

### Rate Limiting
Enable rate limiting to prevent abuse:
```bash
RATE_LIMIT_RPS=50
RATE_LIMIT_BURST=100
RATE_LIMIT_BY_IP=true
```

### Key Management
- Keys rotate automatically based on `KEY_ROTATION_INTERVAL`
- Old keys are retained for `KEY_RETENTION_PERIOD` to handle delayed requests
- Use `SEED_SECRET_KEY` for deterministic key generation in clustered deployments

### Request Validation
The gateway validates:
- Request size limits
- Binary HTTP message format
- Target origin allowlists
- Path traversal attempts

## Monitoring

### Metrics
Prometheus metrics are available at `/metrics`:
- `ohttp_requests_total` - Total requests processed
- `ohttp_request_duration_seconds` - Request processing time
- `ohttp_decryption_errors_total` - Decryption failures
- `ohttp_encryption_errors_total` - Encryption failures
- `ohttp_backend_errors_total` - Backend request failures

### Health Checks
- `/health` - Basic service health
- `/health/keys` - Key management status

### Logging
Structured logging with configurable levels and formats. Set `LOG_FORMAT=json` for machine-readable logs.

## Deployment

### Production Considerations
- Use HTTPS for all external traffic
- Configure proper origin allowlists
- Enable rate limiting and monitoring
- Set appropriate resource limits
- Use a reverse proxy for TLS termination

### Kubernetes Example
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ohttp-gateway
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ohttp-gateway
  template:
    metadata:
      labels:
        app: ohttp-gateway
    spec:
      containers:
      - name: gateway
        image: ohttp-gateway:latest
        ports:
        - containerPort: 8080
        env:
        - name: BACKEND_URL
          value: "https://api.example.com"
        - name: ALLOWED_TARGET_ORIGINS
          value: "api.example.com"
        - name: RATE_LIMIT_RPS
          value: "100"
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

## Development

### Building
```bash
cargo build --release
```

### Testing
```bash
cargo test
```

### Linting
```bash
cargo clippy
cargo fmt
