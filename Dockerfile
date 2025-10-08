# Dockerfile

# ---------- 1. Build Stage ----------
FROM rust:trixie AS builder

# Create a new empty shell project
WORKDIR /app

# Install dependencies needed for build
RUN apt-get update && apt-get install -y pkg-config libssl-dev build-essential && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY core ./core

# Build the project in release mode
RUN cargo build --release -p core-service

# ---------- 2. Runtime Stage ----------
FROM ubuntu:latest

# Create a non-root user
RUN useradd -m appuser

# Install runtime dependencies (e.g., SSL libs)
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/core-service .

# Expose your API port
EXPOSE 3000

# Environment variables (you can override in docker-compose or GitHub Actions)
ENV SERVER_HOST=0.0.0.0
ENV SERVER_PORT=3000

USER appuser

# Run the binary
CMD ["./core-service"]
