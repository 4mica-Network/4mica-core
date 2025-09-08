# Stage 1 - Build
FROM rust:trixie AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Stage 2 - Run
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/core-service /usr/local/bin/core-service
EXPOSE 3000
CMD ["core-service"]
