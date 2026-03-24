# ============================================================================
# Stage 1: Build dependencies (cached unless Cargo.toml/Cargo.lock change)
#
# Copies workspace + crate manifests and dummy sources to cache dep compilation
# as a separate Docker layer that survives source-only changes.
# ============================================================================
FROM rust:1.87-slim-bookworm AS deps

WORKDIR /app

# Workspace manifest + lockfile
COPY Cargo.toml Cargo.lock ./

# Crate manifests
COPY proxy-gateway/Cargo.toml proxy-gateway/
COPY proxy-gateway-core/Cargo.toml proxy-gateway-core/
COPY proxy-gateway-source-bottingtools/Cargo.toml proxy-gateway-source-bottingtools/
COPY proxy-gateway-source-geonode/Cargo.toml proxy-gateway-source-geonode/
COPY proxy-gateway-source-static-file/Cargo.toml proxy-gateway-source-static-file/

# Dummy sources matching the real crate layouts
RUN mkdir -p proxy-gateway/src/bin \
    && echo 'fn main() {}' > proxy-gateway/src/main.rs \
    && echo 'fn main() {}' > proxy-gateway/src/bin/gen_openapi.rs \
    && touch proxy-gateway/src/lib.rs \
    && mkdir -p proxy-gateway-core/src \
    && touch proxy-gateway-core/src/lib.rs \
    && mkdir -p proxy-gateway-source-bottingtools/src \
    && touch proxy-gateway-source-bottingtools/src/lib.rs \
    && mkdir -p proxy-gateway-source-geonode/src \
    && touch proxy-gateway-source-geonode/src/lib.rs \
    && mkdir -p proxy-gateway-source-static-file/src \
    && touch proxy-gateway-source-static-file/src/lib.rs

RUN cargo build --release 2>&1 \
    && rm -rf proxy-gateway/src \
           proxy-gateway-core/src \
           proxy-gateway-source-bottingtools/src \
           proxy-gateway-source-geonode/src \
           proxy-gateway-source-static-file/src

# ============================================================================
# Stage 2: Build the actual binary
# ============================================================================
FROM deps AS builder

COPY proxy-gateway/src/ proxy-gateway/src/
COPY proxy-gateway-core/src/ proxy-gateway-core/src/
COPY proxy-gateway-source-bottingtools/src/ proxy-gateway-source-bottingtools/src/
COPY proxy-gateway-source-geonode/src/ proxy-gateway-source-geonode/src/
COPY proxy-gateway-source-static-file/src/ proxy-gateway-source-static-file/src/

RUN find proxy-gateway/src proxy-gateway-core/src \
        proxy-gateway-source-bottingtools/src \
        proxy-gateway-source-geonode/src \
        proxy-gateway-source-static-file/src \
        -name '*.rs' -exec touch {} +

RUN cargo build --release --bin proxy-gateway \
    && strip target/release/proxy-gateway

# ============================================================================
# Stage 3: Minimal runtime image
# ============================================================================
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin appuser

COPY --from=builder /app/target/release/proxy-gateway /usr/local/bin/proxy-gateway

RUN mkdir -p /data/config && chown appuser:appuser /data/config
VOLUME /data/config

ENV RUST_LOG=info

USER appuser
EXPOSE 8100

ENTRYPOINT ["proxy-gateway"]
CMD ["/data/config/config.toml"]
