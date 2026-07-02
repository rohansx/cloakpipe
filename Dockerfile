# CloakPipe OSS — privacy proxy for LLM traffic.
#
#   docker build -t cloakpipe .
#   docker run -p 8900:8900 -e OPENAI_API_KEY=sk-... cloakpipe
#
# The bundled config (docker/cloakpipe.docker.toml) binds 0.0.0.0:8900 and
# leaves NER disabled, so the image runs the regex/heuristic detector with no
# model download. To use the neural detector, mount your own /app/cloakpipe.toml
# with [detection.ner] enabled = true plus the model files.

FROM rust:1.88-trixie AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p cloakpipe-cli

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y ca-certificates curl libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/cloakpipe /usr/local/bin/cloakpipe
COPY docker/cloakpipe.docker.toml /app/cloakpipe.toml
RUN mkdir -p /data
WORKDIR /app
EXPOSE 8900
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://localhost:8900/health || exit 1
# Required at runtime: OPENAI_API_KEY (upstream provider key CloakPipe forwards).
# Optional: CLOAKPIPE_VAULT_KEY (64-char hex; auto-generated if unset).
CMD ["cloakpipe", "-c", "/app/cloakpipe.toml", "start"]
