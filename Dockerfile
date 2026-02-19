FROM rust:1.93 AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/discourse-discord-bridge /usr/local/bin/

ENTRYPOINT ["discourse-discord-bridge", "/config/config.toml"]
