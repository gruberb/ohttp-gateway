# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-03-10

### Fixed
- **Key ID extraction**: Read `body[0]` instead of `body[1]` per RFC 9458 — there is no version byte in the encapsulated request format. The previous code extracted `0x00` from the KEM ID, causing fallback to the wrong server after key rotation and "Failed to open ciphertext" decapsulation errors.
- **OHTTP key health check**: Replace `config.len() > 100` byte-length heuristic with `active_keys > 0`. A typical X25519 config is ~49 bytes, so valid configs were always reported as "unhealthy".
- **Backend health check**: Use `HEAD /` instead of `GET /health`. Any HTTP response now means the backend is reachable. Only connection failures are marked unhealthy. Error details are included in JSON output for diagnostics.

## [1.0.0] - 2024-11-23

### Added
- RFC 9458 compliant OHTTP gateway implementation
- Automatic key rotation with configurable intervals
- Key management with deterministic and random key generation
- Comprehensive security middleware with rate limiting
- Prometheus metrics integration for observability
- Health check endpoints for monitoring
- Docker support for containerized deployment
- Configurable target origin allowlists
- Request validation and security controls
- Binary HTTP (BHTTP) message handling
- HPKE encryption/decryption for OHTTP protocol
- Graceful shutdown handling
- Structured logging with JSON support
- Configuration through environment variables
- Support for multiple cipher suites (X25519, HKDF-SHA256, AES-128-GCM, ChaCha20-Poly1305)

### Fixed
- **BREAKING**: Key configuration format now includes required 2-byte length prefix per RFC 9458 Section 3.2
- Proper handling of key expiration and cleanup
- Correct OHTTP key configuration encoding with length prefixes
- Memory safety and thread safety improvements

### Technical Details
- Built with Rust 2024 edition
- Uses `ohttp` crate v0.7.1 for RFC 9458 compliance
- Uses `bhttp` crate v0.7.1 for binary HTTP message handling
- Comprehensive test suite with 28+ tests covering all major functionality
- Production-ready error handling and logging

### Dependencies
- axum 0.7 for HTTP server framework
- tokio 1.48 for async runtime
- hyper 1.8 for HTTP implementation
- reqwest 0.12 for backend HTTP client
- ohttp 0.7.1 for OHTTP protocol implementation
- bhttp 0.7.1 for binary HTTP messages
- prometheus for metrics collection
- tracing for structured logging
- chrono for time handling

### Security
- HPKE-based encryption using industry-standard algorithms
- Request size limits and validation
- Origin-based access control
- Rate limiting with configurable thresholds
- Secure key rotation and management
- Protection against replay attacks
- Comprehensive input validation

### Performance
- Connection reuse between relay and gateway
- Efficient binary HTTP message processing
- Optimized cryptographic operations
- Configurable timeouts and limits
- Memory-efficient key storage

This is the first stable release suitable for production use in OHTTP deployments.