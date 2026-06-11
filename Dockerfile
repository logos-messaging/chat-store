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
    && rm -rf src target/release/deps/keypackage_registry* target/release/keypackage-registry

# Now build the real binary; dependency artifacts above are reused.
COPY src ./src
RUN cargo build --release --locked --bin keypackage-registry

########################################
# Runtime stage
########################################
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/keypackage-registry /usr/local/bin/keypackage-registry

# Matches the default --bind 0.0.0.0:8080.
EXPOSE 8080

# Persist the SQLite database on a volume rather than the container layer.
VOLUME ["/data"]
ENV RUST_LOG=info

ENTRYPOINT ["keypackage-registry"]
CMD ["--bind", "0.0.0.0:8080", "--db", "/data/keypackage-registry.db"]
