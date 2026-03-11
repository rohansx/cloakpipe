FROM rust:bookworm AS builder

WORKDIR /src

COPY Cargo.toml ./
COPY crates/cloakpipe-core/Cargo.toml crates/cloakpipe-core/Cargo.toml
COPY crates/cloakpipe-proxy/Cargo.toml crates/cloakpipe-proxy/Cargo.toml
COPY crates/cloakpipe-audit/Cargo.toml crates/cloakpipe-audit/Cargo.toml
COPY crates/cloakpipe-tree/Cargo.toml crates/cloakpipe-tree/Cargo.toml
COPY crates/cloakpipe-vector/Cargo.toml crates/cloakpipe-vector/Cargo.toml
COPY crates/cloakpipe-mcp/Cargo.toml crates/cloakpipe-mcp/Cargo.toml
COPY crates/cloakpipe-local/Cargo.toml crates/cloakpipe-local/Cargo.toml
COPY crates/cloakpipe-cli/Cargo.toml crates/cloakpipe-cli/Cargo.toml

RUN for crate in core proxy audit tree vector mcp local; do \
      mkdir -p crates/cloakpipe-${crate}/src && \
      echo "" > crates/cloakpipe-${crate}/src/lib.rs; \
    done && \
    mkdir -p crates/cloakpipe-cli/src && \
    echo "fn main() {}" > crates/cloakpipe-cli/src/main.rs

RUN cargo build --release --workspace 2>/dev/null || true

COPY crates/ crates/
COPY policies/ policies/

RUN find crates -name "*.rs" -exec touch {} + && \
    cargo build --release --bin cloakpipe

FROM node:22-slim AS dashboard

WORKDIR /dashboard
COPY dashboard/package.json dashboard/package-lock.json* ./
RUN npm ci
COPY dashboard/ .
RUN npm run build

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/bash cloakpipe

WORKDIR /app

COPY --from=builder /src/target/release/cloakpipe /usr/local/bin/cloakpipe

COPY policies/ /app/policies/
COPY cloakpipe.docker.toml /app/cloakpipe.toml

COPY --from=dashboard /dashboard/dist /app/dashboard/

RUN mkdir -p /app/data /app/audit /app/tree_indices && \
    chown -R cloakpipe:cloakpipe /app

USER cloakpipe

EXPOSE 8900

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -sf http://localhost:8900/health || exit 1

ENTRYPOINT ["cloakpipe"]
CMD ["--config", "/app/cloakpipe.toml", "start"]
