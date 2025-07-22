# Build stage
FROM rust:1.88-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Cargo files
COPY Cargo.toml ./

# Create dummy main to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN RUSTFLAGS="-C target-cpu=native" cargo build --release
RUN rm -rf src

# Copy source code
COPY src ./src

# Build the actual application
RUN touch src/main.rs && RUSTFLAGS="-C target-cpu=native" cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/ohttp-gateway /usr/local/bin/ohttp-gateway

# Create non-root user
RUN useradd -m -u 1001 ohttp
USER ohttp

# Set default environment variables
ENV RUST_LOG=debug,ohttp_gateway=debug
ENV PORT=8000
ENV BACKEND_URL=http://localhost:8080
ENV REQUEST_TIMEOUT=30
ENV KEY_ROTATION_ENABLED=false

EXPOSE 8000

CMD ["ohttp-gateway"]
