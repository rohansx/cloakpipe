<p align="center">
  <h1 align="center">CloakPipe</h1>
  <p align="center">
    <strong>Privacy middleware for LLM & RAG pipelines</strong>
  </p>
  <p align="center">
    <a href="https://github.com/rohansx/cloakpipe/actions"><img src="https://img.shields.io/github/actions/workflow/status/rohansx/cloakpipe/ci.yml?style=flat-square" alt="CI"></a>
    <a href="https://crates.io/crates/cloakpipe"><img src="https://img.shields.io/crates/v/cloakpipe?style=flat-square" alt="crates.io"></a>
    <a href="https://github.com/rohansx/cloakpipe/blob/main/LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue?style=flat-square" alt="License"></a>
  </p>
</p>

CloakPipe is a Rust-native proxy that sits between your application and any OpenAI-compatible API. It automatically detects sensitive entities in prompts, replaces them with consistent pseudonyms, forwards the sanitized request, and rehydrates the response before returning it to your app. Your LLM provider never sees real data.

```
Your App  -->  CloakPipe Proxy  -->  LLM API
                  |                     |
            Detect & Replace      Process safely
            "Tata Motors" -> ORG_1      |
                  |                     |
            Rehydrate Response    <-----+
            ORG_1 -> "Tata Motors"
```

## The Problem

Every RAG pipeline that calls an external embedding or LLM API sends sensitive data in plaintext. Revenue figures, client names, API keys, project codenames, internal URLs -- all of it leaves your network on every request.

Naive redaction (`[REDACTED]`) destroys semantic meaning and breaks retrieval. Python-based PII tools add 50-200ms of latency per call and miss financial/business data entirely. Cloud-locked solutions (Bedrock guardrails, OPAQUE) only work within their own ecosystem.

CloakPipe takes a different approach: **consistent pseudonymization**. The same entity always maps to the same token (`ORG_7`, `AMOUNT_12`, `PERSON_5`), preserving semantic structure for embeddings and retrieval while keeping real values out of third-party APIs.

## Features

- **Drop-in proxy** -- OpenAI-compatible API; change one URL and your app is protected
- **Multi-layer detection** -- Regex patterns, financial intelligence, custom TOML rules, optional NER
- **Consistent pseudonymization** -- Same entity always maps to the same token across sessions
- **Encrypted vault** -- AES-256-GCM at rest, `zeroize` memory safety for key material
- **SSE streaming rehydration** -- Token-aware buffering handles pseudonyms split across chunks
- **Audit logging** -- Structured JSONL logs for compliance (metadata only, never raw values)
- **Single binary** -- No Docker, no Python, no microservices. Deploy in seconds
- **<5ms overhead** -- Rust-native, sits in the hot path without you noticing

## Quick Start

### Install from source

```bash
git clone https://github.com/rohansx/cloakpipe.git
cd cloakpipe
cargo build --release
```

### Initialize configuration

```bash
./target/release/cloakpipe init
# Creates cloakpipe.toml with sensible defaults
```

### Set environment variables

```bash
export OPENAI_API_KEY="sk-..."
export CLOAKPIPE_VAULT_KEY=$(openssl rand -hex 32)
```

### Start the proxy

```bash
./target/release/cloakpipe start
# Listening on 127.0.0.1:8900
```

### Point your app at CloakPipe

```python
from openai import OpenAI

# Before -- data sent in plaintext
client = OpenAI()

# After -- data pseudonymized automatically
client = OpenAI(base_url="http://127.0.0.1:8900/v1")
```

That's it. No SDK changes, no framework plugins, no code modifications.

### Works with any OpenAI-compatible client

<details>
<summary><strong>LangChain</strong></summary>

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    openai_api_base="http://127.0.0.1:8900/v1",
    model="gpt-4o",
)
```
</details>

<details>
<summary><strong>LlamaIndex</strong></summary>

```python
from llama_index.llms.openai import OpenAI

llm = OpenAI(
    api_base="http://127.0.0.1:8900/v1",
    model="gpt-4o",
)
```
</details>

<details>
<summary><strong>curl</strong></summary>

```bash
curl http://127.0.0.1:8900/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Summarize Q3 results for Tata Motors"}]
  }'
```
</details>

<details>
<summary><strong>Ollama / local models</strong></summary>

Point CloakPipe upstream at your local Ollama instance:

```toml
[proxy]
upstream = "http://localhost:11434"
```
</details>

## Test Detection (no API key needed)

```bash
# Built-in sample text
./target/release/cloakpipe test

# Custom text
./target/release/cloakpipe test --text "Send $1.2M to alice@acme.com by Q3 2025"

# From file
./target/release/cloakpipe test --file document.txt
```

Example output:

```
Detected 8 entities:
  EMAIL     alice@acme.com         -> EMAIL_1
  AMOUNT    $1.2M                  -> AMOUNT_1
  DATE      Q3 2025                -> DATE_1

Pseudonymized:
  "Send AMOUNT_1 to EMAIL_1 by DATE_1"

Rehydrated:
  "Send $1.2M to alice@acme.com by Q3 2025"

Roundtrip: OK
```

## Configuration

CloakPipe is configured via `cloakpipe.toml`:

```toml
[proxy]
listen = "127.0.0.1:8900"
upstream = "https://api.openai.com"
api_key_env = "OPENAI_API_KEY"
timeout_seconds = 120

[vault]
path = "./vault.enc"
encryption = "aes-256-gcm"
key_env = "CLOAKPIPE_VAULT_KEY"

[detection]
secrets = true           # API keys, JWTs, connection strings
financial = true         # Currency amounts, percentages, fiscal dates
dates = true
emails = true
phone_numbers = true
ip_addresses = true
urls_internal = true

[detection.custom]
patterns = [
    { name = "project_codename", regex = "Project\\s+(Alpha|Beta|Gamma)", category = "PROJECT" },
    { name = "client_tier", regex = "Tier\\s+[A-C]\\s+client", category = "CLASSIFICATION" },
]

[detection.overrides]
preserve = ["OpenAI", "GPT-4", "Claude"]    # Never pseudonymize
force = ["internal-secret"]                  # Always pseudonymize

[audit]
enabled = true
log_path = "./audit/"
log_entities = true    # Log entity metadata (never raw values)
```

## Detection Layers

| Layer | What it catches | Examples |
|-------|----------------|----------|
| **Secrets** | API keys, JWTs, connection strings, tokens | `AKIAIOSFODNN7EXAMPLE`, `eyJhbG...` |
| **Financial** | Multi-currency amounts, percentages, fiscal dates | `$1.2M`, `Rs 3.4L Cr`, `15.7%`, `Q3 2025` |
| **Contact** | Emails, phone numbers, IP addresses, internal URLs | `alice@acme.com`, `192.168.1.1` |
| **Custom** | User-defined TOML patterns | Project codenames, client tiers, internal terms |
| **NER** | Persons, organizations, locations | ONNX-based (optional, `--features ner`) |

## How It Works

1. **Detect** -- Multi-layer engine scans for sensitive entities in the request body
2. **Pseudonymize** -- Replace each entity with a consistent token (`ORG_1`, `EMAIL_3`, `AMOUNT_7`). Mappings are persisted in an AES-256-GCM encrypted vault
3. **Forward** -- Send the sanitized request to the upstream LLM/embedding API
4. **Rehydrate** -- Swap tokens back to original values in the response, including real-time SSE streaming with token-aware chunk buffering
5. **Audit** -- Log request metadata (entity counts, categories, latency) without ever recording raw values

The vault ensures consistency: "Tata Motors" always maps to `ORG_7`, across documents, queries, and sessions. This preserves semantic structure for embeddings and retrieval.

## Project Structure

```
crates/
  cloakpipe-core/       Detection, pseudonymization, vault, rehydration
  cloakpipe-proxy/      Axum HTTP proxy (chat completions + embeddings)
  cloakpipe-cli/        CLI binary (start, test, stats, init)
  cloakpipe-audit/      JSONL audit logging with daily rotation
  cloakpipe-tree/       CloakTree: vectorless retrieval (planned)
  cloakpipe-vector/     Distance-preserving vector encryption (planned)
  cloakpipe-local/      Fully local RAG mode (planned)
```

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.1 | Multi-layer detection, consistent pseudonymization, encrypted vault, OpenAI-compatible proxy, SSE streaming, audit logging | **Released** |
| v0.2 | CloakTree -- vectorless, reasoning-based retrieval for structured documents | Planned |
| v0.3 | ONNX-based NER for person/org/location detection | Planned |
| v0.4 | Distance-preserving vector encryption (ADCPE) | Planned |
| v0.5 | Fully local mode with zero external API calls | Planned |
| v0.6 | TEE support (AWS Nitro Enclaves, Intel TDX) | Planned |

## Running Tests

```bash
cargo test
```

22 tests covering vault encryption, multi-layer detection, pseudonymization roundtrips, streaming rehydration, and end-to-end proxy behavior.

## Security

CloakPipe handles sensitive data by design. Security considerations:

- **Vault encryption**: All entity mappings are encrypted with AES-256-GCM at rest. Keys are never written to disk.
- **Memory safety**: Sensitive key material is deterministically zeroed via `zeroize` -- not left to the garbage collector.
- **Audit trail**: Structured logs record what happened (entity counts, categories, timing) without recording what the entities actually were.
- **No telemetry**: CloakPipe sends zero data anywhere. The proxy connects only to your configured upstream.

If you discover a security vulnerability, please report it privately via [GitHub Security Advisories](https://github.com/rohansx/cloakpipe/security/advisories/new).

## Contributing

Contributions are welcome. Please open an issue to discuss your idea before submitting a PR.

```bash
# Development build
cargo build

# Run tests
cargo test

# Run with tracing
RUST_LOG=debug cargo run -- start
```

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
