# syntax=docker/dockerfile:1

########################################
# Build stage
########################################
# Nix, not the `rust` image: the binary links the native liblogosdelivery, which
# only nix builds. That library comes from nixpkgs' glibc (2.40), newer than
# bookworm's, so cargo has to run against the same nixpkgs — mixing the two
# libcs in one process does not work. Everything below therefore builds inside
# the flake's dev shell.
FROM nixos/nix:2.32.0 AS builder

# `filter-syscalls` off because the seccomp filter fails inside an emulated
# (qemu) container, which is how this image gets built on arm64 hosts.
RUN printf 'experimental-features = nix-command flakes\nfilter-syscalls = false\n' \
    >> /etc/nix/nix.conf

WORKDIR /src

# The native library first and on its own layer: it is by far the slowest part
# of the build and only changes when the flake pins do.
COPY flake.nix flake.lock ./
RUN nix --accept-flake-config build .#logos-delivery --no-link

# Then the Rust dependency graph, against a stub binary, so the (also slow)
# dependency compile is cached and only re-runs when Cargo.toml/Cargo.lock change.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
    && echo "fn main() {}" > src/main.rs \
    && nix --accept-flake-config develop --command cargo build --release --locked \
    && rm -rf src target/release/deps/chat_store* target/release/chat-store

# Now the real binary; dependency artifacts above are reused. `migrations/` is
# needed at build time too — `sqlx::migrate!()` embeds the .sql files.
COPY src ./src
COPY migrations ./migrations
RUN nix --accept-flake-config develop --command \
    cargo build --release --locked --bin chat-store

# Collect what the binary loads at runtime. logos-delivery's build.rs stamps
# liblogosdelivery with an absolute store path as its soname, so the binary
# names it — along with its ELF interpreter and rpath — by absolute /nix/store
# path. Seeding the closure from those three is all the runtime image needs.
RUN nix --accept-flake-config develop --command sh -c '\
      bin=target/release/chat-store; \
      { patchelf --print-needed "$bin"; \
        patchelf --print-interpreter "$bin"; \
        patchelf --print-rpath "$bin" | tr ":" "\n"; } \
      | grep "^/nix/store/" \
      | sed "s|\(/nix/store/[^/]*\).*|\1|" | sort -u \
      | xargs nix-store --query --requisites | sort -u > /closure.txt' \
    && mkdir -p /output/nix/store \
    && cp target/release/chat-store /output/chat-store \
    && cp -a $(cat /closure.txt) /output/nix/store/

########################################
# Runtime stage
########################################
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The nix closure the binary resolves by absolute path, then the binary itself.
COPY --from=builder /output/nix/store /nix/store
COPY --from=builder /output/chat-store /usr/local/bin/chat-store

# Matches the default --bind 0.0.0.0:8080.
EXPOSE 8080

# Persist the SQLite database on a volume rather than the container layer.
VOLUME ["/data"]
ENV RUST_LOG=info

ENTRYPOINT ["chat-store"]
CMD ["--bind", "0.0.0.0:8080", "--db", "/data/chat-store.db"]
