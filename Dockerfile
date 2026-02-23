# ============================================================================
# Stage 1: Build dependencies (cached unless Cargo.toml/Cargo.lock change)
#
# Copies only the manifests and creates dummy source files matching the
# lib + bin layout, then builds. This compiles all dependencies into a
# cached Docker layer that survives source code changes.
# ============================================================================
FROM rust:1.93.1-slim-trixie AS deps

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

# Create dummy source files matching the real crate layout (lib + 2 bins).
RUN mkdir -p src/bin \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > src/bin/gen_openapi.rs \
    && touch src/lib.rs

RUN cargo build --release 2>&1 \
    && rm -rf src

# ============================================================================
# Stage 2: Build the actual binary (deps are cached from stage 1)
# ============================================================================
FROM deps AS builder

COPY src/ src/

# Touch all source files so cargo sees them as newer than the dummies.
RUN find src -name '*.rs' -exec touch {} +

RUN cargo build --release --bin proxy-rotator \
    && strip target/release/proxy-rotator

# ============================================================================
# Stage 3: Minimal runtime image
# ============================================================================
FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /app/target/release/proxy-rotator /usr/local/bin/proxy-rotator

RUN mkdir -p /data/config && chown appuser:appuser /data/config
VOLUME /data/config

ENV RUST_LOG=info

USER appuser
EXPOSE 8100

ENTRYPOINT ["proxy-rotator"]
CMD ["/data/config/config.toml"]
