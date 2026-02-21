FROM rust:1.93 AS builder

WORKDIR /app

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

# Build actual application
COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/discourse-discord-bridge /usr/local/bin/

RUN mkdir -p /data
WORKDIR /data

ENTRYPOINT ["discourse-discord-bridge", "/config/config.toml"]
