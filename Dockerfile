# syntax=docker/dockerfile:1

########################################
# Build stage
########################################
FROM rust:1-bookworm AS builder

# rusqlite's `bundled-sqlcipher-vendored-openssl` feature compiles SQLCipher and
# a vendored OpenSSL from source: the C toolchain ships in the base image, but
# the OpenSSL build also needs perl + make.
RUN apt-get update \
    && apt-get install -y --no-install-recommends perl make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build dependencies first against a stub binary so the (slow) SQLCipher/OpenSSL
# compilation is cached and only re-runs when Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src target/release/deps/chat_store* target/release/chat-store

# Now build the real binary; dependency artifacts above are reused.
COPY src ./src
RUN cargo build --release --locked --bin chat-store

########################################
# Runtime stage
########################################
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/chat-store /usr/local/bin/chat-store

# Matches the default --bind 0.0.0.0:8080.
EXPOSE 8080

# Persist the SQLite database on a volume rather than the container layer.
VOLUME ["/data"]
ENV RUST_LOG=info

ENTRYPOINT ["chat-store"]
CMD ["--bind", "0.0.0.0:8080", "--db", "/data/chat-store.db"]
