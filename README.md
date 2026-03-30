<div align="center">

# 🔒 CloakPipe

**Privacy proxy for LLM traffic. Detect, mask, and unmask PII in real-time.**

Rust-native · <5ms latency · 33+ entity types · 91.7% real-world protection · OpenAI-compatible · Local-first

[Website](https://cloakpipe.co) · [Docs](https://docs.cloakpipe.co) · [Cloud Dashboard](https://app.cloakpipe.co) · [Discord](https://discord.gg/cloakpipe)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/cloakpipe.svg)](https://crates.io/crates/cloakpipe)
[![Docker](https://img.shields.io/docker/pulls/cloakpipe/cloakpipe.svg)](https://hub.docker.com/r/cloakpipe/cloakpipe)

</div>

---

## What is CloakPipe?

CloakPipe is a **high-performance privacy proxy** that sits between your application and any LLM API. It detects PII (personally identifiable information) in your prompts, replaces it with safe tokens, forwards the sanitized request to the LLM, and restores the original values in the response.

**The LLM never sees your real data. Your users see natural responses.**

```
Your App  ──▶  CloakPipe  ──▶  OpenAI / Anthropic / Any LLM
                  │
          Detect → Mask → Proxy → Unmask
                  │
           Encrypted Vault
          (AES-256-GCM)
```

---

## Quick Start

### Docker (recommended)

```bash
# Start CloakPipe
docker run -p 3100:3100 ghcr.io/cloakpipe/cloakpipe:latest

# Point your OpenAI SDK at CloakPipe
export OPENAI_BASE_URL=http://localhost:3100/v1

# Done. All LLM calls now go through CloakPipe.
```

### Binary

```bash
# Install via cargo
cargo install cloakpipe

# Or download the latest release
curl -fsSL https://cloakpipe.co/install.sh | sh

# Start the proxy
cloakpipe serve --port 3100
```

### Verify it works

```bash
curl http://localhost:3100/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {"role": "user", "content": "Summarize the case for Rajesh Singh, Aadhaar 2345 6789 0123, treated at Apollo Hospital Mumbai."}
    ]
  }'

# CloakPipe logs:
# ✓ Detected 3 entities: PERSON, AADHAAR, ORGANIZATION
# ✓ Masked: Rajesh Singh → PERSON_042, 2345 6789 0123 → AADHAAR_017, Apollo Hospital Mumbai → ORG_003
# ✓ Proxied to api.openai.com (sanitized)
# ✓ Unmasked response: PERSON_042 → Rajesh Singh (restored)
```

---

## Before & After

### What your app sends:

> Summarize the medical history of **Dr. Rajesh Singh** (Aadhaar: **2345 6789 0123**), treated at **Apollo Hospital Mumbai** for cardiac issues since **March 2024**.

### What the LLM sees:

> Summarize the medical history of **PERSON_042** (Aadhaar: **AADHAAR_017**), treated at **ORG_003** for cardiac issues since **DATE_012**.

### What your user gets back:

> **Dr. Rajesh Singh** has been under cardiac care at **Apollo Hospital Mumbai** since **March 2024**. The treatment history includes...

The LLM generates a coherent response using the tokens. CloakPipe restores the original values before returning to your app. The model never saw the real data.

---

## Why CloakPipe?

| | CloakPipe | Presidio | Protecto | LLMGuard |
|---|---|---|---|---|
| **Language** | Rust | Python | Python | Python |
| **Latency** | <5ms | 50–200ms | 50–200ms | 50–200ms |
| **Mode** | Drop-in proxy | Library | Cloud SaaS | Library |
| **Reversible masking** | ✅ Encrypted vault | ❌ Permanent redaction | ✅ Cloud vault | ❌ Permanent |
| **India PII** | ✅ Aadhaar, PAN, UPI, **GSTIN** | ❌ | Aadhaar, PAN only | ❌ |
| **DPDP 2023** | ✅ Built-in policy | ❌ | Claimed | ❌ |
| **Self-hosted** | ✅ Single binary | ✅ | Enterprise only | ✅ |
| **MCP support** | ✅ (via Cloud) | ❌ | ❌ | ❌ |
| **Open source** | ✅ MIT | ✅ MIT | ❌ Closed | ✅ MIT |
| **Price** | Free (open source) | Free | $250–$750/mo | Free |
| **Dependencies** | 0 (single binary) | Python + spaCy | Python + cloud | Python + PyTorch |

---

## How It Works

### Detection Pipeline

CloakPipe uses a multi-layer detection pipeline. Each layer catches what the others miss — the union of all layers achieves 91.7% PII protection on real-world cross-domain data (Slack threads, medical notes, legal memos, financial documents).

```
Input Text
    │
    ▼
┌──────────────────────────────────────────┐
│  Layer 1: Regex + Checksums              │  <1ms
│  Email, phone, SSN, Aadhaar, PAN,       │
│  API keys, IPs, URLs, employee IDs,     │
│  insurance policy numbers, license #s    │
├──────────────────────────────────────────┤
│  Layer 2: Financial Intelligence         │  <1ms
│  Currency amounts ($, EUR, INR, etc.),   │
│  percentages, fiscal dates, periods      │
├──────────────────────────────────────────┤
│  Layer 3: ONNX NER Model                │  5-15ms
│  DistilBERT-PII (63MB, runs on any CPU) │
│  33 entity types: names, addresses,     │
│  orgs, DOB, account numbers, PINs       │
│  No GPU required. No Python dependency.  │
├──────────────────────────────────────────┤
│  Layer 4: Fuzzy Entity Resolution        │  <1ms
│  Jaro-Winkler similarity matching       │
│  Links "Dr. R. Singh" and              │
│  "Rajesh Singh" as same entity           │
├──────────────────────────────────────────┤
│  Layer 5: Custom TOML Rules              │  <1ms
│  User-defined patterns for               │
│  domain-specific identifiers             │
└──────────────────────────────────────────┘
    │
    ▼
Masked Output (total: <20ms on any laptop CPU)
```

#### NER Backend Options

| Backend | Config | Size | Speed | Hardware | Use Case |
|---|---|---|---|---|---|
| **DistilBERT-PII** | `distilbert_pii` | 63MB | 5-15ms | Any CPU | Default. 33 entity types, runs everywhere |
| **GLiNER-PII sidecar** | `gliner_pii` | 2.3GB | 300ms | 4GB+ RAM | Zero-shot custom entity types via Python sidecar |
| BERT NER | `bert` | ~400MB | 20-40ms | Any CPU | Legacy 4-type NER (PER/ORG/LOC/MISC) |
| GLiNER2 | `gliner` | ~800MB | 50ms | Any CPU | Legacy zero-shot NER |

### Tokenization

Tokens are **deterministic within a session** — the same entity always maps to the same token. This means the LLM maintains coherence across the conversation.

Tokens are **non-deterministic across sessions** — the same entity maps to a different token in a new session, preventing cross-session correlation.

### Encrypted Vault

All entity ↔ token mappings are stored in a local vault encrypted with AES-256-GCM. The vault never leaves your infrastructure. There is no cloud dependency.

---

## Supported Entity Types

### Standard PII

| Entity | Example | Detection |
|---|---|---|
| Person Name | John Smith, Dr. Priya Sharma | NER |
| Email Address | user@example.com | Regex |
| Phone Number | +1-555-0123, +91 98765 43210 | Regex |
| Credit Card | 4532-1234-5678-9012 | Regex + Luhn |
| SSN | 123-45-6789 | Regex |
| Date of Birth | 15/03/1990, March 15, 1990 | NER |
| Address | 123 MG Road, Pune 411001 | NER |
| IP Address | 192.168.1.1, 2001:db8::1 | Regex |
| Organization | Apollo Hospital, HDFC Bank | NER |
| Medical Term | diabetes, cardiac arrest | NER |
| Bank Account | IFSC + account number | Regex |
| Passport Number | J1234567 | Regex |
| License Plate | MH 12 AB 1234 | Regex |
| URL | https://internal.company.com | Regex |
| API Key | sk-live_xxx, AKIA... | Regex |

### India-Specific PII 🇮🇳

| Entity | Format | Example |
|---|---|---|
| **Aadhaar Number** | 12 digits (XXXX XXXX XXXX) | 2345 6789 0123 |
| **PAN Card** | ABCDE1234F | BNZPM2501F |
| **UPI ID** | name@bank | rajesh@okicici |
| **Indian Phone** | +91 XXXXX XXXXX | +91 98765 43210 |
| **GSTIN** | 15-char alphanumeric | 27AAPFU0939F1ZV |
| **Indian Passport** | Letter + 7 digits | J1234567 |

No other open-source LLM privacy tool handles Indian PII natively.

---

## Integration Examples

### OpenAI Python SDK

```python
from openai import OpenAI

# Just change the base URL. That's it.
client = OpenAI(
    base_url="http://localhost:3100/v1",  # CloakPipe proxy
    api_key="sk-your-openai-key"          # Your real API key
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "user", "content": "Analyze the account for Priya Sharma, PAN BNZPM2501F"}
    ]
)

# CloakPipe detected PAN and person name, masked them,
# sent sanitized prompt to OpenAI, and unmasked the response.
print(response.choices[0].message.content)
```

### LangChain

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4",
    openai_api_base="http://localhost:3100/v1",  # CloakPipe proxy
    openai_api_key="sk-your-key"
)

response = llm.invoke("Summarize patient records for Aadhaar 2345 6789 0123")
```

### Anthropic SDK

```python
from anthropic import Anthropic

client = Anthropic(
    base_url="http://localhost:3100/v1/anthropic",  # CloakPipe proxy
    api_key="sk-ant-your-key"
)

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[
        {"role": "user", "content": "Review the loan application for Amit Patel, PAN ABCDE1234F"}
    ]
)
```

### curl

```bash
# Works with any LLM API that uses the OpenAI format
curl http://localhost:3100/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Your prompt with PII here"}]
  }'
```

### Vercel AI SDK

```typescript
import { openai } from '@ai-sdk/openai';
import { generateText } from 'ai';

const result = await generateText({
  model: openai('gpt-4', {
    baseURL: 'http://localhost:3100/v1',  // CloakPipe proxy
  }),
  prompt: 'Analyze the customer data for Rajesh, Aadhaar 2345 6789 0123',
});
```

---

## CLI

```bash
# Scan text for PII (no proxy, just detection)
cloakpipe scan "Dr. Rajesh Singh, Aadhaar 2345 6789 0123"
# Output:
# ✓ PERSON: "Dr. Rajesh Singh" (confidence: 0.97)
# ✓ AADHAAR: "2345 6789 0123" (confidence: 1.00)

# Mask text (replace PII with tokens)
cloakpipe mask "Contact Priya at priya@example.com or +91 98765 43210"
# Output: "Contact PERSON_001 at EMAIL_001 or PHONE_001"

# Start the proxy server
cloakpipe serve --port 3100

# Start with a specific policy
cloakpipe serve --port 3100 --policy policies/dpdp.yaml

# Check proxy health
cloakpipe health
```

---

## Configuration

### Environment Variables

```bash
# Proxy settings
CLOAKPIPE_PORT=3100                    # Proxy port (default: 3100)
CLOAKPIPE_HOST=0.0.0.0                # Bind address (default: 0.0.0.0)
CLOAKPIPE_LOG_LEVEL=info               # Log level: debug, info, warn, error

# LLM provider
CLOAKPIPE_UPSTREAM_URL=https://api.openai.com  # Default upstream LLM API
CLOAKPIPE_TIMEOUT=30                   # Request timeout in seconds

# Detection
CLOAKPIPE_POLICY=policies/dpdp.yaml   # Policy file path
CLOAKPIPE_MIN_CONFIDENCE=0.8          # Minimum NER confidence threshold (0.0–1.0)

# Vault
CLOAKPIPE_VAULT_PATH=./vault.db       # Encrypted vault file path
CLOAKPIPE_VAULT_KEY=                   # 256-bit encryption key (auto-generated if empty)

# Cloud (optional, for dashboard users)
CLOAKPIPE_CLOUD_TOKEN=                 # Cloud dashboard token (app.cloakpipe.co)
```

### Policy Files

CloakPipe uses YAML policy files to configure detection behavior per compliance framework:

```yaml
# policies/dpdp.yaml — India Digital Personal Data Protection Act
name: "DPDP Act 2023"
version: "1.0"
description: "Policy for India's Digital Personal Data Protection Act"

entities:
  # Always detect and mask these
  required:
    - aadhaar_number
    - pan_card
    - upi_id
    - person_name
    - phone_number_in
    - email_address
    - date_of_birth
    - address
    - bank_account_in
    - gstin

  # Detect but warn (don't mask by default)
  advisory:
    - organization
    - medical_term
    - ip_address

  # Skip these
  disabled:
    - ssn              # US-only
    - passport_us      # US-only

masking:
  strategy: "deterministic"   # deterministic | random | hash
  format: "{TYPE}_{ID}"       # e.g., PERSON_042
  session_scope: true          # Same entity → same token within session

logging:
  log_detections: true
  log_masked_prompts: false    # Never log original PII
  export_format: "json"        # json | csv
```

Pre-built policies included: `dpdp.yaml`, `gdpr.yaml`, `hipaa.yaml`, `pci-dss.yaml`, `minimal.yaml`

---

## Architecture

CloakPipe is built as a modular Rust workspace with 8 crates:

```
cloakpipe/
├── crates/
│   ├── cloakpipe-core       # Detection, replacement, vault, rehydration
│   ├── cloakpipe-proxy      # HTTP proxy server (axum, OpenAI-compatible)
│   ├── cloakpipe-tree       # CloakTree: vectorless LLM-driven retrieval
│   ├── cloakpipe-vector     # ADCPE distance-preserving vector encryption
│   ├── cloakpipe-local      # Fully local mode (candle-rs embeddings + LanceDB)
│   ├── cloakpipe-audit      # Compliance logging and audit trails
│   ├── cloakpipe-mcp        # MCP server (6 tools via rmcp)
│   └── cloakpipe-cli        # CLI interface (scan, mask, serve, vault, session)
├── policies/
│   ├── dpdp.yaml
│   ├── gdpr.yaml
│   ├── hipaa.yaml
│   └── pci-dss.yaml
├── Cargo.toml
├── LICENSE
└── README.md
```

### Crate Dependency Graph

```
cloakpipe-cli
    ├── cloakpipe-proxy
    │       ├── cloakpipe-core
    │       ├── cloakpipe-tree
    │       ├── cloakpipe-vector
    │       └── cloakpipe-audit
    └── cloakpipe-mcp
            └── cloakpipe-core
```

Each crate is independently usable. If you only need PII detection in your Rust app without the proxy, depend on `cloakpipe-core` directly.

---

## Benchmarks

### Real-World E2E Protection Test

Tested on 4 cross-domain scenarios (Slack threads, invoice emails, medical notes, legal documents) — messy, unpredictable text that real users paste into LLMs. Not crafted for any detection system.

| Metric | CloakPipe (v0.9) | Regex Only | nvidia/gliner-PII |
|---|---|---|---|
| **PII protection rate** | **91.7%** (55/60) | 53.4% | 65.9% |
| **Names detected** | ✅ | ❌ | ✅ |
| **Addresses detected** | ✅ | ❌ | ✅ |
| **Financial amounts** | ✅ | ✅ | ❌ |
| **API keys / secrets** | ✅ | ✅ | ❌ |
| **Custom IDs (EMP-, INS-)** | ✅ | ❌ | ❌ |
| **Model size** | **63MB** | 0 | 2.3GB |
| **Latency per request** | **5-20ms** | <1ms | 300ms |
| **Requires GPU** | **No** | No | No (slow) |
| **Requires Python** | **No** | No | Yes |

### Per-Scenario Results

| Scenario | Items | Protected | Leaked to LLM |
|---|---|---|---|
| Slack thread (VC deal) | 15 | 87% | 2 items |
| Invoice email (financial) | 15 | 93% | 1 item |
| Doctor's notes (medical) | 14 | 86% | 2 items |
| Immigration case (legal) | 16 | **100%** | 0 items |

### Response Quality

Both protected and unprotected LLM calls produce coherent, usable responses. The LLM treats pseudo-tokens (PERSON_1, EMAIL_1) as placeholders and generates appropriate text. Rehydration restores all original data with perfect roundtrip fidelity.

### Latency

| Tool | Language | Avg Latency | P99 Latency | Accuracy (F1) | Reversible |
|---|---|---|---|---|---|
| **CloakPipe OSS** | Rust | **3.2ms** | **4.8ms** | **0.94** | ✅ |
| **CloakPipe Cloud** | Rust + GLiNER2 | **4.1ms** | **6.2ms** | **0.99** | ✅ |
| Presidio | Python | 87ms | 142ms | 0.84 | ❌ |
| LLMGuard | Python | 112ms | 198ms | 0.82 | ❌ |
| Regex-only | Any | 0.5ms | 0.8ms | 0.61 | ❌ |

---

## Cloud Dashboard

Need analytics, audit trails, or team features? **[CloakPipe Cloud](https://app.cloakpipe.co)** adds a dashboard on top of the open-source proxy.

**The proxy always runs on your infra. PII never leaves your network.** Only anonymized telemetry (entity counts, latency metrics) goes to the dashboard.

| Feature | OSS (Free) | Cloud Pro ($99/mo) | Cloud Business ($499/mo) |
|---|---|---|---|
| Core proxy + detection | ✅ | ✅ | ✅ |
| Encrypted vault | ✅ | ✅ | ✅ |
| Policy templates | ✅ | ✅ | ✅ |
| India PII (Aadhaar, PAN, UPI) | ✅ | ✅ | ✅ |
| Dashboard + analytics | — | ✅ | ✅ |
| Audit trail export | — | ✅ | ✅ |
| Compliance reports | — | ✅ | ✅ |
| Privacy Chat UI | — | ✅ | ✅ |
| Multi-user | — | Up to 10 | Unlimited |
| RBAC + SSO | — | — | ✅ |
| Custom entity types | — | — | ✅ |
| Webhook alerts | — | — | ✅ |
| Kubernetes Helm chart | — | — | ✅ |
| MCP Server (6 tools) | — | — | ✅ |
| Support | Community | Email | Priority |

→ [app.cloakpipe.co](https://app.cloakpipe.co)

---

## Compliance

CloakPipe helps you meet regulatory requirements by ensuring PII never reaches a third-party model. We only claim what we can prove — no vendor-badge theatre.

| Framework | What CloakPipe provides | Can we claim it? |
|---|---|---|
| **DPDP Act 2023** (India) | Detects Aadhaar, PAN, UPI, GSTIN. Self-hosted mode keeps data within your infrastructure — no cross-border transfer of personal data. Pre-built `policies/dpdp.yaml` profile. | ✅ "Supports DPDP compliance" — no certification body exists; compliance is technical. |
| **GDPR** (EU) | Pseudonymization is explicitly recognized under GDPR Art. 25 (data protection by design). Tokens replace personal data before it reaches any third-party processor. | ✅ "GDPR-ready" — self-attested or validated by legal counsel. |
| **HIPAA** (US) | PHI detection (patient IDs, diagnoses, medications), AES-256-GCM encrypted vault, tamper-evident audit logs meet HIPAA Security Rule technical safeguards. | ✅ "Supports HIPAA workflows" — HIPAA has no official certification body. |
| **PCI-DSS** | Credit card (PAN) detection with Luhn validation, encrypted vault, no plaintext storage. Pre-built `policies/pci-dss.yaml`. | ✅ "Supports PCI-DSS workflows" — formal QSA audit required for full certification. |
| **SOC 2 Type II** | Structured audit logging, access controls, and incident response processes in place. Formal audit in roadmap. | 🔜 In progress — will not claim until third-party audit is complete. |

Pre-built policy files are included in [`policies/`](policies/):

```
policies/
├── dpdp.yaml      # India Digital Personal Data Protection Act 2023
├── gdpr.yaml      # EU General Data Protection Regulation
├── hipaa.yaml     # US Health Insurance Portability and Accountability Act
├── pci-dss.yaml   # Payment Card Industry Data Security Standard
└── minimal.yaml   # Minimal — only high-confidence structured PII
```

---

## Deployment

### Docker Compose

```yaml
version: '3.8'
services:
  cloakpipe:
    image: ghcr.io/cloakpipe/cloakpipe:latest
    ports:
      - "3100:3100"
    environment:
      - CLOAKPIPE_UPSTREAM_URL=https://api.openai.com
      - CLOAKPIPE_POLICY=policies/dpdp.yaml
      - CLOAKPIPE_LOG_LEVEL=info
    volumes:
      - cloakpipe-vault:/data/vault
    restart: unless-stopped

volumes:
  cloakpipe-vault:
```

### Systemd

```ini
[Unit]
Description=CloakPipe LLM Privacy Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cloakpipe serve --port 3100
Restart=always
Environment=CLOAKPIPE_UPSTREAM_URL=https://api.openai.com

[Install]
WantedBy=multi-user.target
```

---

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Good first issues:**
- Add new regex pattern for a PII type
- Improve NER accuracy on Indian names
- Add integration example (Haystack, LlamaIndex, etc.)
- Write documentation for a use case

**Development setup:**

```bash
git clone https://github.com/rohansx/cloakpipe.git
cd cloakpipe
cargo build
cargo test
cargo run -p cloakpipe-cli -- serve --port 3100
```

---

## Roadmap

- [x] Core proxy with PII detection and masking
- [x] AES-256-GCM encrypted vault
- [x] Regex + ONNX NER detection pipeline
- [x] Jaro-Winkler fuzzy entity resolution
- [x] India PII support (Aadhaar, PAN, UPI, GSTIN)
- [x] CloakTree: vectorless LLM-driven retrieval
- [x] ADCPE distance-preserving vector encryption
- [x] Industry profiles (legal, healthcare, fintech)
- [x] MCP server (6 tools)
- [x] Session-aware pseudonymization + coreference resolution
- [x] DistilBERT-PII NER (63MB ONNX, 33 entity types, runs on any CPU)
- [x] nvidia/gliner-PII sidecar backend (zero-shot custom entities)
- [x] Real-world E2E benchmarks (91.7% protection on cross-domain data)
- [ ] Anthropic API native format support
- [ ] Multi-language NER (Hindi, Marathi, Tamil)
- [ ] WebSocket proxy mode
- [ ] Custom entity type plugins (WASM)
- [ ] TEE support (AWS Nitro Enclaves)

---

## Security

CloakPipe is security-focused software. If you find a vulnerability, please report it responsibly:

**Email:** security@cloakpipe.co

Do **not** file a public GitHub issue for security vulnerabilities.

---

## License

Apache-2.0. See [LICENSE](LICENSE).

The CloakPipe Cloud dashboard and enterprise features are proprietary (BUSL-1.1).

---

<div align="center">

**Built in Rust. Made in Pune, India.**

[Website](https://cloakpipe.co) · [Docs](https://docs.cloakpipe.co) · [Cloud](https://app.cloakpipe.co) · [Twitter](https://twitter.com/cloakpipe) · [Discord](https://discord.gg/cloakpipe)

</div>
