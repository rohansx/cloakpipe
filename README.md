<p align="center">
  <h1 align="center">CloakPipe</h1>
  <p align="center">
    <strong>Privacy middleware for LLM & RAG pipelines</strong>
  </p>
  <p align="center">
    <a href="https://github.com/rohansx/cloakpipe/actions"><img src="https://img.shields.io/github/actions/workflow/status/rohansx/cloakpipe/ci.yml?style=flat-square" alt="CI"></a>
    <a href="https://crates.io/crates/cloakpipe-core"><img src="https://img.shields.io/crates/v/cloakpipe-core?style=flat-square&label=crates.io" alt="crates.io"></a>
    <a href="https://github.com/rohansx/cloakpipe/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  </p>
</p>

CloakPipe is a Rust-native privacy proxy for LLM and RAG pipelines. It sits between your application and any OpenAI-compatible API, automatically detecting sensitive entities, replacing them with consistent pseudonyms, and rehydrating responses -- so your LLM provider never sees real data.

<p align="center">
  <img src="assets/cloakpipe-demo.gif" alt="CloakPipe Demo" width="800">
</p>

## The Problem

Every RAG pipeline that calls an external API sends sensitive data in plaintext:

```
                        WITHOUT CLOAKPIPE
                        =================

 Your App                              LLM / Embedding API
    |                                        |
    |  "Tata Motors reported Rs 3.4L Cr      |
    |   revenue. Contact: cfo@tata.com       |
    |   AWS key: AKIAIOSFODNN7EXAMPLE"       |
    |                                        |
    +--------- PLAINTEXT over HTTPS -------->|  <-- Provider sees everything
    |                                        |
    |  "Tata Motors reported strong Q3..."   |
    |<---------------------------------------+
```

Naive redaction (`[REDACTED]`) destroys semantic meaning and breaks retrieval. Python PII tools add 50-200ms latency and miss financial data. Cloud-locked solutions only work within their own ecosystem.

## The Solution: Consistent Pseudonymization

CloakPipe replaces sensitive entities with **consistent tokens** that preserve semantic structure:

```
                         WITH CLOAKPIPE
                         ==============

 Your App              CloakPipe Proxy              LLM API
    |                       |                          |
    |  "Tata Motors         |                          |
    |   reported Rs 3.4L    |                          |
    |   Cr revenue in       |                          |
    |   Q3 2025. Contact:   |                          |
    |   cfo@tata.com"       |                          |
    +---------------------->|                          |
                            |                          |
                     DETECT & PSEUDONYMIZE             |
                     +-------------------------+       |
                     | Tata Motors  -> ORG_7    |       |
                     | Rs 3.4L Cr  -> AMOUNT_12|       |
                     | Q3 2025     -> DATE_3   |       |
                     | cfo@tata.com-> EMAIL_5  |       |
                     +-------------------------+       |
                            |                          |
                            |  "ORG_7 reported         |
                            |   AMOUNT_12 revenue      |
                            |   in DATE_3. Contact:    |
                            |   EMAIL_5"               |
                            +------------------------->|
                            |                          |
                            |  "ORG_7 had strong       |  Provider sees
                            |   AMOUNT_12 growth..."   |  only pseudonyms
                            |<-------------------------+
                            |
                     REHYDRATE RESPONSE
                     +-------------------------+
                     | ORG_7      -> Tata Motors|
                     | AMOUNT_12  -> Rs 3.4L Cr|
                     +-------------------------+
                            |
    |  "Tata Motors had     |
    |   strong Rs 3.4L Cr   |
    |   growth..."          |
    |<----------------------+

    User sees real data.
    LLM never saw it.
```

The same entity **always maps to the same token** across documents, queries, and sessions. This means:
- Embeddings preserve semantic structure (vector search still works)
- Multi-turn conversations stay coherent
- The LLM reasons over pseudonyms, and rehydration restores real values

## Where CloakPipe Sits in a RAG Pipeline

```
 Documents                          User Queries
     |                                   |
     v                                   v
 +---------+                       +-----------+
 | Chunker |                       | Query     |
 +---------+                       +-----------+
     |                                   |
     v                                   v
 +--------------------------------------------------+
 |                   CLOAKPIPE                       |
 |                                                   |
 |  +------------+  +-------+  +-----------------+  |
 |  | Detection  |->| Vault |->| Pseudonymize    |  |
 |  | Engine     |  | (AES) |  | (consistent)    |  |
 |  +------------+  +-------+  +-----------------+  |
 |   regex|finance|custom|NER    entity -> token     |
 +--------------------------------------------------+
     |                                   |
     v                                   v
 Embedding API                     LLM API
 (sees pseudonyms)                 (sees pseudonyms)
     |                                   |
     v                                   v
 Vector DB                         +--------------------------------------------------+
 (pseudonymized                    |                   CLOAKPIPE                       |
  embeddings)                      |  +-----------------+  +-------+                   |
     |                             |  | Rehydrate       |->| Vault |                   |
     +--- retrieve context ------->|  | (streaming SSE) |  | (AES) |                   |
                                   |  +-----------------+  +-------+                   |
                                   +--------------------------------------------------+
                                                             |
                                                             v
                                                        User sees
                                                        real data
```

**4 leak points in a standard RAG pipeline. CloakPipe covers all of them.**

## Features

- **Drop-in proxy** -- OpenAI-compatible API; change one URL and your app is protected
- **Multi-layer detection** -- Regex patterns, financial intelligence, custom TOML rules, optional NER
- **Consistent pseudonymization** -- Same entity always maps to the same token across sessions
- **Encrypted vault** -- AES-256-GCM at rest, `zeroize` memory safety for key material
- **SSE streaming rehydration** -- Token-aware buffering handles pseudonyms split across chunks
- **Audit logging** -- Structured JSONL logs for compliance (metadata only, never raw values)
- **Industry profiles** -- Pre-tuned detection for legal, healthcare, fintech; guided setup wizard
- **MCP server** -- Expose privacy tools to AI agents (Claude, Cursor, custom harnesses)
- **Single binary** -- No Docker, no Python, no microservices. Deploy in seconds
- **<5ms overhead** -- Rust-native, sits in the hot path without you noticing

## Quick Start

### Install from crates.io

```bash
cargo install cloakpipe-cli
```

### Or build from source

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

## Industry Profiles

CloakPipe ships with pre-tuned detection profiles for different industries:

```bash
# Interactive setup wizard — choose your industry, provider, and vault backend
cloakpipe setup
```

| Profile | What it adds | Use case |
|---------|-------------|----------|
| **General** | Balanced defaults — secrets, financial, dates, emails | Most applications |
| **Legal** | Case numbers, docket IDs, SSNs, bar numbers | Law firms, legal tech |
| **Healthcare** | MRN, NPI, DEA numbers, ICD codes (HIPAA-aware) | Health tech, clinical AI |
| **Fintech** | SWIFT/BIC, ISIN, IBAN, routing numbers, IP detection | Banking, trading platforms |

Set in config:
```toml
profile = "healthcare"
```

Or switch at runtime via the MCP `configure` tool or API.

## MCP Server (Agentic Integrations)

CloakPipe exposes its privacy tools as an [MCP](https://modelcontextprotocol.io) server, so AI agents (Claude Code, Cursor, custom agents) can pseudonymize data as a skill:

```bash
cloakpipe mcp
```

**Available tools:**

| Tool | Description |
|------|-------------|
| `pseudonymize` | Detect and replace sensitive entities with consistent tokens |
| `rehydrate` | Restore pseudo-tokens back to original values |
| `detect` | Dry-run scan — see what would be caught without replacing |
| `vault_stats` | Show total mappings and per-category counts |
| `configure` | Switch industry profile or toggle detection categories at runtime |

**Claude Desktop / Claude Code config:**

```json
{
  "mcpServers": {
    "cloakpipe": {
      "command": "cloakpipe",
      "args": ["mcp"]
    }
  }
}
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

```
Request Flow:

  Incoming request
       |
       v
  +------------------+     +------------------+     +------------------+
  |  1. DETECT       |---->|  2. PSEUDONYMIZE |---->|  3. FORWARD      |
  |                  |     |                  |     |                  |
  |  Multi-layer     |     |  Entity -> Token |     |  Sanitized req   |
  |  engine scans    |     |  stored in AES   |     |  to upstream API |
  |  request body    |     |  encrypted vault |     |                  |
  +------------------+     +------------------+     +------------------+
                                                           |
  +------------------+     +------------------+            |
  |  5. AUDIT        |<----|  4. REHYDRATE    |<-----------+
  |                  |     |                  |
  |  Log metadata    |     |  Token -> Entity |    Response Flow
  |  (never raw      |     |  in response,    |    (including SSE
  |   values)        |     |  including SSE   |     streaming)
  +------------------+     |  streaming with  |
                           |  chunk buffering |
                           +------------------+
                                  |
                                  v
                           Response to app
                           (real values restored)
```

**Key design decisions:**
- **Consistent mappings** -- "Tata Motors" always maps to `ORG_7`, across all documents, queries, and sessions
- **Encrypted vault** -- Mappings persisted with AES-256-GCM; keys zeroed from memory via `zeroize`
- **Streaming-aware** -- SSE rehydration handles tokens split across chunks (e.g., `OR` + `G_7`)
- **Metadata-only audit** -- Logs record entity counts and categories, never the actual values

## Project Structure

| Crate | crates.io | Description |
|-------|-----------|-------------|
| [`cloakpipe-cli`](crates/cloakpipe-cli/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-cli?style=flat-square)](https://crates.io/crates/cloakpipe-cli) | CLI binary (`start`, `test`, `stats`, `init`, `setup`, `mcp`, `tree`, `vector`) |
| [`cloakpipe-core`](crates/cloakpipe-core/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-core?style=flat-square)](https://crates.io/crates/cloakpipe-core) | Detection, pseudonymization, vault (file + SQLite), rehydration, industry profiles |
| [`cloakpipe-proxy`](crates/cloakpipe-proxy/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-proxy?style=flat-square)](https://crates.io/crates/cloakpipe-proxy) | Axum HTTP proxy (chat completions + embeddings) |
| [`cloakpipe-audit`](crates/cloakpipe-audit/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-audit?style=flat-square)](https://crates.io/crates/cloakpipe-audit) | Audit logging (JSONL + SQLite) with rotation |
| [`cloakpipe-tree`](crates/cloakpipe-tree/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-tree?style=flat-square)](https://crates.io/crates/cloakpipe-tree) | CloakTree: vectorless document retrieval |
| [`cloakpipe-vector`](crates/cloakpipe-vector/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-vector?style=flat-square)](https://crates.io/crates/cloakpipe-vector) | ADCPE: distance-preserving vector encryption |
| [`cloakpipe-mcp`](crates/cloakpipe-mcp/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-mcp?style=flat-square)](https://crates.io/crates/cloakpipe-mcp) | MCP server for agentic integrations |
| [`cloakpipe-local`](crates/cloakpipe-local/) | [![crates.io](https://img.shields.io/crates/v/cloakpipe-local?style=flat-square)](https://crates.io/crates/cloakpipe-local) | Fully local RAG mode (planned) |

## Roadmap

| Version | Feature | Status |
|---------|---------|--------|
| v0.1 | Multi-layer detection, consistent pseudonymization, encrypted vault, OpenAI-compatible proxy, SSE streaming, audit logging | **Released** |
| v0.2 | CloakTree — vectorless, reasoning-based retrieval for structured documents | **Released** |
| v0.3 | ONNX NER, SQLite vault/audit, multi-user support | **Released** |
| v0.4 | Distance-preserving vector encryption (ADCPE) | **Released** |
| v0.5 | Industry profiles, MCP server for agentic integrations, guided setup wizard | **Released** |
| v0.6 | Fully local mode with zero external API calls | Planned |
| v0.7 | TEE support (AWS Nitro Enclaves, Intel TDX) | Planned |

## Running Tests

```bash
cargo test
```

57 tests covering vault encryption, multi-layer detection, pseudonymization roundtrips, streaming rehydration, SQLite vault/audit, ADCPE vector encryption, industry profiles, MCP server tools, and end-to-end proxy behavior.

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

This project is licensed under the [MIT License](LICENSE).
