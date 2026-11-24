# Changelog

All notable changes to CloakPipe are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
CloakPipe is pre-1.0 and its formats carry `v1alpha1` versions, so minor releases
may contain breaking changes; these are marked **Breaking**.

## [Unreleased]

## [0.15.0] - 2026-11-24

Writing the first contract was the biggest hurdle to adopting the gate.
`cloakpipe infer` now drafts it from what the agent actually does, and
`cloakpipe prove` shows the contract working against a live agent.

### Added

- `mcp-proxy --capture <dir>`: opt-in local capture of every `tools/call`
  (raw arguments, before the gate and any PII transform), every `tools/list`
  reply and the task context, for `infer`. Shadow mode (or no manifest) only;
  owner-only files that never leave the machine. `--capture-shapes` keeps
  only each string's length, pattern class and a salted hash (task binding
  still works); `--capture-max-age DAYS` prunes old captures
  ([docs/INFER.md](docs/INFER.md)).
- `cloakpipe infer <captures>`: drafts a manifest from captured calls:
  tools, types, ranges, enums, patterns, task binding (`one_of_context`,
  with an `or_pattern` for recurring internal domains) and suggested
  approvals. Outliers (calls the agent may have been tricked into) are
  excluded and listed for review, never widened into a rule. Every rule
  carries its support, confidence and a redacted example. The draft is loaded
  with the gate's own parser and checked against every captured call; it is
  never activated. `--diff <manifest>` reports new tools, refused calls and
  rules that could be tightened, exiting 1 on drift for CI.
- `cloakpipe prove --agent agent.yaml --contract <manifest> --pack
  support-basics --runs N --sandbox local|docker|e2b`: runs a live agent
  through an attack pack with the gate in shadow and in enforce mode, and
  reports which attacks reached the tools, which were refused and why, and
  whether normal work still completes. The built-in `support-basics` pack
  covers exfiltration by email, an undeclared tool, an oversized refund, a
  double side effect, argument stretching and a control. HTML and JSON
  reports; every enforce run's ledger is exported and verified offline.
  Exits 1 when an attack reaches a tool or false refusals exceed
  `--max-false-refusal-rate` ([docs/PROVE.md](docs/PROVE.md)).

### Changed

- **Breaking** (library): `cloakpipe_mcp::ProxyContext` has a new field,
  `capture: Option<Capture>`; struct literals need `capture: None`.

## [0.14.0] - 2026-10-29

Approvals can now go through a broker, such as CloakPipe Cloud or your own:
the gate files a signed approval request carrying only the arguments the
manifest lists in `approval.show`, polls for signed receipts in the
background, and verifies each receipt locally before writing it, so the
decision path never waits on the network.

### Added

- Approvals through a broker ([docs/APPROVALS.md](docs/APPROVALS.md)), an
  open protocol any service can implement (CloakPipe Cloud does):
  - `mcp-proxy --approvals-url <broker>/v1/gates/<id>
    --approvals-secret-file FILE [--approvals-poll-interval 5s]`. A call
    refused as `approval_required` is filed with a signed
    `POST <url>/approvals` (`cloakpipe.approval-request/v1`: fingerprint,
    release, tool, approver routes, task id, ttl, ledger seq and only the
    `approval.show` values), queued and sent in the background, once per
    fingerprint while open. A poller fetches finished requests with a
    signed `GET <url>/approvals?since=<cursor>`, verifies each receipt
    against `--approver-key`, the release, tool, task id, fingerprint and
    ttl, and only then writes it atomically to `--approvals`; one that does
    not verify is not written and raises `approval.mismatch`. Decisions
    never wait on the broker; if it is down, approvals do not arrive.
    A polled record whose `task_id` names another task (another gate
    process sharing the gate URL) is skipped quietly. Needs `--approvals`, `--approver-key` and a task context with a
    `taskId`, checked at start-up.
  - The refusal's `error.data` gains `approval_request` (`requested`,
    `pending` or `denied`) and a `hint` to retry after approval.
  - A new reason, `approval_denied`: an approver denied this exact call,
    and it is refused until the denial's `not_after` (else the request's
    ttl), without filing a new request. The gate also honours a
    `<fingerprint hex>.denied.json` marker in the approvals directory,
    with or without a broker. An expired request is `approval_required`
    again and is filed anew; `approval_expired` still means a receipt past
    its `notAfter`.
  - `cloakpipe approvals keys --approvals-url URL --approvals-secret-file
    FILE --out DIR` writes the broker's approver public keys
    (`GET <url>/approver-keys`) as `--approver-key` files, refusing any key
    whose keyid is not its own.
  - Library: `cloakpipe_mcp::broker` (`ApprovalBroker`, `BrokerConfig`,
    `RequestStatus`), `ToolGate::with_broker` / `request_approval`,
    `Denial::ApprovalDenied`.
- Manifest: `approval.show: [amount, ticket_id]`, the top-level arguments
  whose values an approval broker may see (default: none). Names must be
  declared arguments, not of type object or array; only scalar values are
  sent. `ApprovalRule::shown`. A fingerprint of
  low-entropy arguments can be guessed by brute force; see
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

### Changed

- **Breaking (library):** `cloakpipe_release::rules::ApprovalRule` has a
  new public field, `show`.

## [0.13.0] - 2026-10-28

The gate now runs over MCP's HTTP transport on both sides, fronts several
MCP servers with pinned tool definitions, and delivers its events to signed
webhooks (Slack, Discord or generic), OpenTelemetry and a JSONL log. The
Docker image runs the gate by default.

### Added

- MCP over HTTP (Streamable HTTP, spec rev 2025-06-18) on both sides of
  the gate, with the same decisions, refusals and ledger entries as stdio:
  - `mcp-proxy --listen ADDR` serves agents on `POST /mcp` (JSON
    responses; `Mcp-Session-Id` issued on `initialize` and required after
    it; `DELETE` ends a session; `GET /mcp` is 405), `GET /health` with
    the release name and digest, `Origin` checks, and an optional
    `--listen-token-file` bearer token (scheme case-insensitive). An
    agent's `notifications/cancelled` reaches the upstream under the
    gate's id for that session's own request, and never cancels another
    session's. The bound address is printed on stderr; SIGTERM stops it
    cleanly.
  - `mcp-proxy --upstream-url URL [--upstream-header 'Name: value'|'Name: env:VAR']`
    fronts an HTTP MCP server (JSON or SSE replies, session id and
    protocol version carried). It is mutually exclusive with `--upstream`,
    `--server` and `--tools-lock`; `--upstream-header` without it is a
    usage error.
  - Upstream transport errors fail closed: `upstream_unavailable`
    (JSON-RPC `-32003`), or `unknown` (recorded) for a side-effecting
    call that was sent. Library: `Interceptor::on_upstream_error`,
    `UpstreamTransport::Http`, `Upstream::http`, `cloakpipe_mcp::http::serve`.
  - `--listen` also fronts several stdio servers and a tools lock
    (`--server`, `--tools-lock`; library `cloakpipe_mcp::http::serve_servers`).
  - Not yet: SSE response streams and a `GET` stream to HTTP agents
    (upstream notifications are not relayed to them), and HTTP servers
    behind `--server`/`--tools-lock`.
- Gate events (`cloakpipe_mcp::events`, library API): the MCP gate hands
  each decision worth attention to `ProxyContext::events` sinks after its
  ledger entry is written: `decision.deny`, `approval.requested`,
  `approval.mismatch`, `shadow.finding`, `side_effect.replayed`,
  `side_effect.unknown`, `tool.drift` and `anchor.failed`.
  Each event names its ledger entry (`ledger_seq`, `entry_hash`), carries a
  deterministic fingerprint (`sha256(kind|reason|tool|path|policy_version)`)
  and never an argument value; `GateEvent::to_json` is the stable
  `cloakpipe.event/v1` form, delivered by the flags below.
- The MCP interceptor is now a transport-agnostic `Interceptor` (agent and
  upstream messages in, `Action`s out) with named upstreams (`Upstream`;
  the single `--upstream` is server `default`). `run_proxy` /
  `run_proxy_io` are unchanged; decisions are unchanged.
  **Breaking (library)**: `ProxyContext` has a new `events` field, so a
  struct literal needs `events: Vec::new()`.
- Event delivery (docs/EVENTS.md). New `mcp-proxy` flags:
  - `--events-log PATH` appends each event to a JSONL file.
  - `--webhook URL` (repeatable) POSTs each event, signed with
    `--webhook-secret-file` as `CloakPipe-Signature:
    t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>.<body>"))`, together with
    `CloakPipe-Event` and `CloakPipe-Fingerprint` headers.
    `--webhook-format generic|slack|discord` picks raw JSON, a Slack Block
    Kit message or a Discord embed.
  - `--otel-endpoint URL` (or `--otel` with `OTEL_EXPORTER_OTLP_ENDPOINT`)
    exports one `cloakpipe.decision` span per tool-call decision, allows
    included, over OTLP/HTTP JSON.

  Delivery runs on background threads with bounded queues: three tries,
  5 s timeout, drops counted on stderr, and a flush of up to 5 s on exit.
  It never delays or changes a decision.

  Also new:
  - `cloakpipe events test` sends a sample event, and `cloakpipe events
    verify-signature` checks a signature the way a receiver should.
  - A failed scheduled anchor is now an `anchor.failed` event.
  - Library: `JsonlSink`, `WebhookSink`, `OtelSink`, `DecisionRecord`,
    `AnchorLoop::spawn_with`. `EventSink` gains default `decision` and
    `flush` methods.

- `mcp-proxy --server NAME=COMMAND` (repeatable): one gate in front of
  several stdio MCP servers. The gate initializes and lists every server at
  start-up, answers `initialize`/`ping` itself, merges `tools/list` (all
  pages), routes each `tools/call` to the server that serves the tool under
  its own request ids, and sends other requests to the server named
  `default` (`--upstream`) or the only one, else refuses them (`-32601`).
  A tool name two servers share refuses to start unless the manifest
  declares it per server as `<server>__<tool>`. Library:
  `Interceptor::with_servers`, `run_servers[_io]`, `servers`, `ServerTools`.
  A server that exits fails its open requests closed at once
  (`upstream_unavailable`; a side-effecting call is recorded `unknown`)
  while the other servers serve on.
- Tool pinning: `cloakpipe tools pin` writes `cloakpipe.tools.lock` (per
  server, per tool, sha256 over the JCS of `name`, `description`,
  `inputSchema`, `annotations`, under a lock digest); `cloakpipe tools diff`
  shows added/removed/changed tools (exit 1 on changes); `mcp-proxy
  --tools-lock` hides a tool that does not match its pin (or has none) from
  `tools/list` and refuses calls to it as `tool_drift`, recorded in the
  ledger and emitted as `tool.drift`. Without a lock, a tool whose
  definition changes during the session is refused until restart (also
  with a plain `--upstream`). Decision entries carry the lock digest
  (`tools_lock`) when there is one; entries without it hash as before, so
  older ledgers still verify. **Breaking (library)**: `Denial` has new
  variants (`ToolDrift`, `ToolUnavailable`), and `GateEvent` (`server`) and
  `DecisionDraft`/`DecisionEntry` (`tools_lock`) have new fields.
- `docker/compose.example.yaml` (the gate in front of an example MCP
  server over HTTP) and `examples/support-agent/mock_http_upstream.py`
  (the example's tools over Streamable HTTP).
- Every `v*` tag is now published to crates.io by the release workflow
  (`CARGO_REGISTRY_TOKEN` repo secret). A manual run with a `tag` input
  publishes an existing tag to crates.io without rebuilding the image.
  Re-runs skip crate versions already on crates.io, and crates.io's
  new-crate rate limit (HTTP 429) is waited out and retried.

### Changed

- **Breaking (Docker)**: the image runs the MCP gate over HTTP by default.
  Its entrypoint (`docker/gate-entrypoint.sh`) builds `cloakpipe mcp-proxy
  --listen 0.0.0.0:8900 --manifest /app/cloakpipe.manifest.yaml
  --upstream-url $CLOAKPIPE_UPSTREAM_URL ...` from `CLOAKPIPE_*`
  variables, and refuses to start without an upstream, a mounted manifest,
  or (on a non-loopback address) `CLOAKPIPE_LISTEN_TOKEN_FILE`. The
  ledger, gate key and operations store are on the `/data` volume
  (`CLOAKPIPE_HOME=/data`). The PII proxy is `docker run IMAGE start`; the
  root `docker-compose.yml` now runs it that way.

## [0.12.0] - 2026-10-27

CloakPipe is now a self-hosted policy-enforcement gate for AI agent tool
calls: declare a single-file manifest (and optional Cedar policy), enforce it
in `cloakpipe mcp-proxy`, and prove every decision with a signed, hash-chained
ledger you can export and verify offline. Eval certification, RAG tooling and
the ONNX NER detectors are now opt-in cargo features; the default binary is
the lean gate. Licence: MIT only.

### Added

- `cloakpipe-cli` cargo features `ner`, `rag` and `full` (= `ner`, `rag`,
  `certification`). CI tests the default build and `--features full`, and
  `tools/check_dep_boundary.sh` fails if the default `cloakpipe-cli` or
  `cloakpipe-proxy` dependency tree contains `ort`, `tokenizers`, `ureq`,
  `cloakpipe-cert`, `cloakpipe-tree` or `cloakpipe-vector`.
- crates.io metadata on every crate (`homepage`, `readme`, `keywords`,
  `categories`) and versions on all path dependencies; `cloakpipe-local`,
  `cloakleak` and `cloakleak-cli` are `publish = false`.
- **Single-file manifest, `cloakpipe.manifest.yaml`** (`cloakpipe_release::v1`,
  `schemas/cloakpipe.manifest.schema.json`): top-level `release`, `version`,
  optional `policy` (a file path; its bytes are digested as `policy_digest`)
  and `tools`. Closed by default: a declared tool takes only the `args` it
  lists (none without `args`), each optional unless `required: true`.
  Constraint keys `type`, `pattern`, `enum`, `const`, `min_len`, `max_len`,
  `min`, `max`, `items`, `properties`, plus `one_of_context` (task context
  paths; string or array values) with an `or_pattern` fallback. Per tool:
  `side_effect` / `effect: read|write|irreversible`, an `idempotency_key`
  template (`"{ticket_id}:{sha256(body)}"`) that names the operation, and
  `approval: {when, approvers, ttl}` with a small condition language
  (`amount > 100 && currency == 'EUR'`). Everything is checked at load, so
  a bad rule stops the gate at start-up. The manifest digest is sha256 over
  the JCS form of the parsed document.
- `cloakpipe mcp-proxy --manifest` auto-detects the format (top-level
  `release`: v1; `apiVersion`: legacy). An `approval_required` refusal now
  carries the tool's `approvers` routes and the call `fingerprint`, and a
  receipt valid for longer than the tool's `ttl` is `approval_invalid`.
  `approve` and `action fingerprint` take a v1 manifest too.
- `cloakpipe manifest validate <file>` and `cloakpipe manifest hash <file>
  [--json]` (release, version, manifest_digest, policy_digest).
- Decision ledger: `cloakpipe mcp-proxy` appends one entry per gate decision
  (`cloakpipe.decision/v1`: allow, deny or require_approval for each
  `tools/call`, messages refused unread, side-effect outcomes
  committed/failed/unknown, replays and `operations reconcile`). Entries
  carry seq, ts, release, tool, a keyed `args_fingerprint` (never raw
  values), decision, reason, policy_version (the manifest digest),
  policy_digest (the Cedar policy file's sha256, when the manifest has
  one), mode, task_id and outcome,
  are hash-chained, and each is signed with Ed25519 by the gate signing key
  (`--signing-key` / `CLOAKPIPE_SIGNING_KEY`, else
  `$CLOAKPIPE_HOME/gate.key`, created owner-only on first use with its
  public key printed once). `cloakpipe ledger entries | public-key` and
  `cloakpipe-verify decisions <entries.jsonl> --key …` verify them offline.
- `mcp-proxy --mode enforce|shadow`: shadow forwards every call the gate can
  read and records what enforce mode would have decided (`mode: shadow`).
- Scheduled anchoring: `mcp-proxy --anchor-every N` / `--anchor-interval
  DURATION` seals the decision ledger into numbered, signed epochs
  (`cloakpipe.epoch/v1`, each linked to the previous one) and anchors each
  with an RFC 3161 TSA and Sigstore Rekor on a background thread, off the
  request path (`--tsa`, `--tsa-root`, `--rekor`, `--rekor-key`, `--no-tsa`,
  `--no-rekor`; freetsa.org and rekor.sigstore.dev with built-in trust by
  default). Receipts are kept in the ledger database; a failure prints
  `anchor.failed` and is retried, by later runs too.
- `cloakpipe ledger export --out audit-pack.tar [--since/--until]`: a plain
  tar with entries.jsonl, the gate public key, every epoch with its RFC 3161
  token and Rekor entry, the manifest digests and a pack manifest signed by
  the gate key.
- `cloakpipe verify audit-pack.tar [--key …]`: offline verification of the
  pack with the `cloakpipe-verify` library (also `cloakpipe-verify pack
  audit-pack.tar`). It reports entries, chain and signatures, anchored
  epochs (RFC 3161 and Rekor inclusion proofs), gaps (missing epochs,
  uncovered seq ranges, unanchored epochs), denials, approvals and unknown
  side effects reconciled, and exits non-zero on any failure or gap.
- `cloakpipe-anchor`: `TsaClient::anchor_artifact` and
  `RekorClient::anchor_artifact` anchor any bytes; the `testkit` feature
  (tests only) adds local `MockTsa` and `MockRekor` authorities.

- `examples/support-agent/`: a support agent whose prompt-injected
  `send_email` to an attacker is refused (`scope_mismatch` on `/to`, bound to
  the ticket's customer), on one `cloakpipe.manifest.yaml` with an
  idempotent `send_email` and a refund that needs approval over 100, a
  stdlib-only mock MCP server and the exact commands and output. The test
  suite runs it.
- **Cedar policies in the tool gate** (new crate `cloakpipe-policy`, on
  `cedar-policy` 4.x). The policy a v1 manifest references (`policy:`) is
  parsed at start-up (an invalid one refuses to start) and evaluated for
  every call that passed its contract: principal `Release::"<release>"`,
  action `Action::"<tool>"` (`Tool::"<tool>"` is accepted too), resource
  `Call::"<fingerprint>"` with the arguments as `resource.args`, and a
  context of the task context, persistent per-tool counters
  (`context.counters.<tool>_1h` / `_24h`) and the time. Decision order is
  contract, Cedar, approval: no permit or a forbid is `policy_denied` (the
  refusal and the ledger hop name the deciding policies by `@id`); a call
  whose satisfied permits all carry `@approval("<route>")` needs a receipt,
  with the routes merged into `approval_required`; any evaluation error is
  `fail_closed`. Without `policy:` the gate is contract-only, as before.
- `mcp-proxy --state-db` (default `$CLOAKPIPE_STATE_DB`, else
  `$CLOAKPIPE_HOME/state.db`, `~/.cloakpipe` by default): the SQLite store
  of the policy counters. Only forwarded calls are counted, and the counts
  survive a restart. `cloakpipe manifest validate` parses the policy too.
- `examples/support-agent/policies/support.cedar`: the spec's email rate
  limit (50 an hour) and refund tiers (up to 100; 100 to 500 with
  `@approval`).
- `AgentRelease::gate_issues()` (`cloakpipe-release`): what the tool gate
  needs from a release (known `apiVersion`/`kind`, agent name, well-formed
  and distinct `tool:` and `policy:` references), without the certification
  pins `validate()` requires.

- Docs for the gate: `docs/MANIFEST.md` (format reference),
  `docs/POLICY.md` (Cedar entities, context, counters, decisions),
  `docs/THREAT_MODEL.md` and `docs/KEYS.md` (gate key, approver keys,
  anchoring roots, rotation; KMS/HSM on the roadmap), and
  `examples/filesystem`, a read-only manifest and Cedar policy for the
  reference filesystem MCP server, used by the README's Claude Code, Cursor
  and Codex snippets.
- `tools/check_docs.py`, run in CI: every `cloakpipe` / `cloakpipe-verify`
  command in the README, `docs/` and `examples/*/README.md` (code blocks,
  inline code, MCP host configs) must exist in the default binary with the
  flags shown, and walkthroughs marked `<!-- check-docs: run -->` (the
  README quickstart, the support-agent example, the manifest, policy and key
  docs) are executed and their output compared with the docs. The
  filesystem walkthrough, which downloads the server with `npx`, runs in a
  push-only `docs-network` job.

### Changed

- README rewritten around the action boundary ("Model proposes. Code
  disposes."): a 60-second quickstart with the support-agent example (v1
  manifest + Cedar, the prompt-injected email refused, the ledger exported
  and verified), Declare / Enforce / Prove, host snippets, what it is not
  and an honest roadmap. The support-agent example README now runs as
  written with `cloakpipe` on `PATH`, and ends with a pinned-key `verify`.
- The certification-era docs moved to `docs/legacy/` and are marked legacy:
  `CERTIFICATION.md`, the release `AUDIT_PACK.md`, `AGENT_RELEASE.md`, and
  the 2025 proxy `ARCHITECTURE.md`, `TECH.md` and `PLAN.md` (which showed
  commands that never existed).
- `cloakpipe verify` / `cloakpipe-verify pack` with several `--key`s (a
  rotated gate key) named the first pinned key as the pack's signer; it now
  names the key that signed `pack.json`.
- `cloakpipe operations reconcile --manifest` read only the legacy Agent
  Release and failed on a v1 `cloakpipe.manifest.yaml` with "unknown field
  `release`"; it now takes either format and binds the reconciliation entry
  to the manifest digest.
- **Breaking (build): the default `cloakpipe` binary is the lean gate**:
  `mcp-proxy` and its evidence tooling, plus regex PII detection for `start`,
  `scan`, `mcp` and `mcp-proxy --transform pii`. It no longer links ONNX
  Runtime, tokenizers, the RAG crates or `cloakpipe-cert`. Build with
  `--features ner` for the NER detectors (a config with `[detection.ner]
  enabled = true` now warns and runs on regex in a build without them),
  `--features rag` for `tree`, `vector` and the proxy's `/v1/embeddings` and
  `/tree/*` routes, `--features certification` for `eval`, `release certify`,
  `release verify-cert` and `release audit-pack`, or `--features full` for all
  of it. The Docker image takes `--build-arg CLOAKPIPE_FEATURES=...`.
- **Licence: MIT only.** `cloakpipe-anchor`, `cloakpipe-verify`, `cloakleak`
  and `cloakleak-cli` (and the CloakLeak sample corpus) move from Apache-2.0
  and CC-BY-4.0 to MIT, under the one root `LICENSE`.
- The workspace and crate descriptions describe the tool-call gate
  ("Self-hosted policy-enforcement gate for AI agent tool calls") instead of
  a privacy proxy.
- `cedar-policy-core` turns on serde_json's `preserve_order` feature, so
  `mcp-proxy` now forwards an agent's JSON-RPC message with its keys in the
  order the agent sent them (they used to be sorted). Digests and
  fingerprints are unaffected: they hash the JCS (RFC 8785) form.
- The support-agent example declares the refund `amount` as an integer.
- **Breaking:** the denial for an argument the contract does not declare is
  `undeclared_argument` (was `argument_not_allowed`), for legacy tool
  contracts too.
- **Deprecated:** the AgentRelease + ToolContract pair (`--tool-contract`).
  It still works for this release, with a warning on stderr; `--tool-contract`
  with a v1 manifest is a usage error, since its contracts are inline.
- **Breaking (`cloakpipe mcp-proxy`): gate decisions are recorded by
  default** in `$CLOAKPIPE_HOME/ledger.db` (`~/.cloakpipe/ledger.db`), or
  `--ledger-db` / `CLOAKPIPE_LEDGER_DB`; `--no-ledger` opts out with a
  warning. A ledger or key that cannot be opened stops the gate, and an
  entry that cannot be written refuses its call as `fail_closed` (never
  forwarded). Gate refusals, approvals and operation states are recorded as
  decision entries instead of `gate_denial` / `gate_violation` /
  `operation_state` metadata on PII hop records; those hop records are now
  written only by `--transform pii`, and old ones are still read.
  `operations reconcile` records a signed `reconcile` entry by default
  instead of an `operation_reconciled` hop.
- `mcp-proxy --gate warn` is now a hidden alias of `--mode shadow`.
- **Breaking (`cloakpipe-mcp`):** `GateMode::Warn` is `GateMode::Shadow`;
  `ProxyContext` has a `decisions` field; `reconcile_operation` takes a
  `DecisionLog` and the release as `sha256:` text.
- **Breaking (`cloakpipe mcp-proxy`): PII masking is opt-in.** By default
  the proxy forwards tool-call arguments and results unchanged: the gate
  allows or refuses a call and never rewrites an allowed one, so a tool now
  receives `dana@customer.example` where 0.11 sent `EMAIL_1`. No vault is
  opened or keyed, and `CLOAKPIPE_VAULT_KEY` and the config file are not
  read. `--transform pii` restores the 0.11 behaviour (pseudonymize PII in
  arguments, rehydrate tokens in results, through the vault); users who
  relied on masking must add it.
- **Breaking (`cloakpipe mcp-proxy --operations-db`):** without
  `--transform pii`, the proxy refuses to start (exit 1, naming
  `--transform pii`) when the operations database holds `done` operations
  whose stored results are masked, since a retry would replay pseudonym
  tokens the agent cannot read. Every result 0.11 stored counts as masked.
  Start with `--transform pii` and the vault the results were masked with
  (the retry is replayed rehydrated, never re-executed), or use a new
  `--operations-db`. The `operations` table gains a nullable
  `result_masked INTEGER` column, added in place when an existing database
  is opened.
- **Breaking (`cloakpipe-mcp` API):** `ProxyContext { detector, vault, .. }`
  is now `ProxyContext { pii: Option<PiiTransform>, .. }`, with
  `PiiTransform { detector, vault }`. `Begin::Replay` carries `masked`,
  `OperationRow` carries `result_masked`, and `OperationStore` gains
  `settle_masked` and `masked_results`. Ledger hops of a proxy without the
  transform record `ActionKind::Passthrough` instead of `Pseudonymize`.
- **Breaking (`cloakpipe mcp-proxy`): the tool gate no longer requires a
  certification.** With `--manifest`, a call is allowed when the release
  declares the tool and the call passes the tool contracts the release binds
  (and approvals / operations, as before). Calls that 0.11 refused as
  `uncertified`, `expired`, `revoked`, `invalid`, `blocked` or
  `wrong_environment` are now forwarded. Default builds no longer accept
  `--certification`, `--trust`, `--trust-key`, `--revoked-statement`,
  `--revoked-key` or `--environment` (clap rejects them, exit 2). The old
  behaviour is a legacy, source-only cargo feature, `certification`, off by
  default (`cargo build -p cloakpipe-cli --features certification`), kept
  until certification is removed; published binaries are built without it.
- **Breaking (`cloakpipe mcp-proxy`):** the gate loads `--manifest` with
  `AgentRelease::gate_issues()` instead of the certifiability checks, so a
  release needs no code commit, prompts, model or pinned runtime image to
  run the gate. A release whose tool or policy references the gate cannot
  read still refuses to start (exit 1).
- `cloakpipe-release`: `spec.code`, `spec.prompts`, `spec.model` and
  `spec.runtime` may be omitted (they read as empty, which `validate()` and
  `release validate` still report). Hashes of manifests that set them are
  unchanged.
- **Breaking (`cloakpipe-mcp` API):** `ToolGate::new(mode, &manifest)` takes
  no certification arguments. With the `certification` feature,
  `ToolGate::with_certification(environment, envelope, verify)` restores the
  requirement, and `Denial::{Uncertified, NotCertified, WrongEnvironment}`
  exist only in that build. `cloakpipe-mcp` no longer depends on
  `cloakpipe-cert` by default; `tools/check_dep_boundary.sh` now checks it.
- CI: a new `test-legacy-features` job runs
  `cargo test --workspace --features certification`.
- **New crate `cloakpipe-receipt`.** The DSSE layer (`Envelope`,
  `Signature`, `TrustedKey`, `pae`, `sign`, `verified_keyids`,
  `NoDuplicateKeys`, `parse_rfc3339`) and approval receipts
  (`cloakpipe_receipt::approval`) moved out of `cloakpipe-cert`, so the MCP
  gate can verify approvals without the certification pipeline.
  `cloakpipe_cert::statement` and `cloakpipe_cert::approval` re-export them
  for one release; the types are the same, not copies.
- **Breaking (`cloakpipe-verify`):** release audit packs (the `pack` module
  and the `cloakpipe-verify release-pack` command) are behind the new
  `release-pack` cargo feature, off by default, so the default verifier, and
  the ledger and anchor crates that depend on it, no longer pull in
  `cloakpipe-cert`. A verifier built without the feature answers
  `release-pack` with a usage error (exit 2) naming the feature. The
  `cloakpipe` CLI enables it for `release audit-pack`. CI checks the
  dependency boundary with `tools/check_dep_boundary.sh`.

### Fixed

- `mcp-proxy` in a `certification` (or `full`) build no longer refuses every
  call as `uncertified` when no certification flag is given: the legacy
  certification gate applies only with `--certification`, `--trust`,
  `--trust-key`, `--revoked-*` or `--environment`.


## [0.11.0] - 2026-10-12

### Added

- **Tool contracts (action boundary).** A new `kind: ToolContract` artifact
  (`cloakpipe_release::contract`, `schemas/tool-contract.schema.json`) gives
  argument-level rules for the tools a release calls: closed argument lists,
  a small deterministic subset of JSON Schema, and `bindTo: task.<key>` to pin
  an argument to a trusted task context. A release binds a contract in
  `spec.policies` as `policy:tool-contract/<name>@sha256:<digest>`, so it is
  covered by the certified release hash. `cloakpipe mcp-proxy` takes
  `--tool-contract` (repeatable) and `--task-context` (or
  `CLOAKPIPE_TASK_CONTEXT`), refuses to start unless the contracts are exactly
  the ones the release binds, and checks each covered call's raw arguments
  before masking. New denial reasons `argument_missing`,
  `argument_not_allowed`, `argument_invalid`, `scope_mismatch`,
  `task_context_missing` and `approval_required`; denial hops carry the
  contract path as `gate_path`. See `docs/ACTION_BOUNDARY.md` and
  `examples/action-boundary/`.
- **Signed approval receipts (action boundary).** A contract tool with
  `requiresApproval: true` now runs only with a signed receipt for the exact
  call: an in-toto Statement (predicate type
  `https://cloakpipe.co/attestations/approval/v1alpha1`) in a DSSE envelope
  whose subject is the call fingerprint, SHA-256 over
  `cloakpipe.co/tool-call/v1` and the JCS of `{release, tool, arguments}`
  (`cloakpipe_release::action`, `cloakpipe_cert::approval`). New commands
  `cloakpipe action fingerprint` and `cloakpipe approve`; `cloakpipe
  mcp-proxy` takes `--approvals <dir>` and `--approver-key` (repeatable). New
  denial reasons `approval_invalid` and `approval_expired`; an approved call's
  `mcp_tool_call` hop records the receipt digest (`approval`) and
  `operation_id`, never the arguments or their fingerprint. New library API
  `ToolGate::with_approvals` and `ToolGate::authorize`.
- **Operation identity and outcome states (action boundary).** A contract
  tool with `sideEffect: true` now runs as a tracked operation in a SQLite
  operations store (`cloakpipe mcp-proxy --operations-db`, or
  `CLOAKPIPE_OPERATIONS_DB`; required for such tools, so the proxy refuses to
  start without it). The operation id is the approval receipt's
  `operationId`, else derived from the task and the call
  (`cloakpipe.co/operation/v1`, an HMAC keyed by the operations database's
  own random key, so the ledger's ids cannot be used to guess arguments);
  the model never supplies it. States
  `in_flight`, `done`, `failed`, `unknown` and `not_applied`: a retry of a
  `done` call replays the stored result (`_meta.cloakpipe.replayed`), a call
  whose reply was lost (upstream exit, broken pipe, crash) becomes `unknown`
  and retries are refused with `reconcile_before_retry` (JSON-RPC `-32002`)
  until an operator runs the new `cloakpipe operations reconcile <id>
  --outcome done|not-applied` (`cloakpipe operations list` shows them;
  an `in_flight` operation needs `--force`). One proxy per operations
  database: a running proxy holds `<db>.lock`, and a second one refuses to
  start. A new operations database is created `0600` on unix.
  New denial reasons `operation_conflict`, `reconcile_before_retry`,
  `request_id_missing`, `request_id_in_use` and `operations_unavailable`.
  Ledger hops carry `operation_id` and `operation_state`, and a new hop
  category `operation_reconciled` (`Hop::OperationReconciled`) records each
  reconciliation; the verifier and audit pack count it by type. New library
  API `cloakpipe_mcp::operations`, `ToolGate::with_operations`,
  `ToolGate::ready` and `cloakpipe_mcp::reconcile_operation`.
- **Agent Release manifests.** A new `cloakpipe-release` crate gives an AI agent
  release an exact, verifiable identity: an `AgentRelease` manifest that only
  accepts immutable references, a canonical hash (RFC 8785), a material-change
  diff that lists the assurance suites a change requires, and in-toto export.
  New commands: `cloakpipe release validate | hash | diff | inspect | register`.
  Ledger records and MCP interceptor hops can be bound to a release hash. Ships
  with a JSON schema, a Python reference implementation of the hash and
  `docs/AGENT_RELEASE.md`.
  ([#12](https://github.com/rohansx/cloakpipe/pull/12))
- **Certification.** A new `cloakpipe-cert` crate makes a deterministic
  certify/block decision for a release from its evaluation runs and a
  certification policy (coverage, pass rate, regressions, critical failures,
  metric thresholds), and signs the result as an in-toto statement in a DSSE
  envelope that verifies offline. New commands: `cloakpipe release keygen`,
  `release certify` (exit 0 only when certified) and `release verify-cert`.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- **Certification GitHub Action.** A reusable `certify` composite action
  (`.github/actions/certify`) lets CI block a release that fails its policy.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- **Evaluation import.** `cloakpipe eval import` turns existing test and eval
  results into evidence for certification: JUnit XML and native JSON
  ([#13](https://github.com/rohansx/cloakpipe/pull/13)), Braintrust experiments
  and Langfuse dataset runs with a configurable `--pass-threshold`
  ([#15](https://github.com/rohansx/cloakpipe/pull/15)). Malformed, duplicate or
  conflicting input is rejected rather than guessed.
- **Langfuse experiments import.** `cloakpipe eval import --langfuse-experiment
  FILE --langfuse-experiment-items FILE` reads the Langfuse experiments API,
  which replaces dataset runs, with cursor pagination, item-count and duplicate
  checks, and `tools/fetch_langfuse_experiment.sh` to download every page.
  ([#20](https://github.com/rohansx/cloakpipe/pull/20))
- **Two-way boundary certification.** A certification policy's optional
  `rules.boundary` stops a release passing authorization by refusing
  everything: cases labelled `expect: allow|deny` (JUnit property
  `cloakpipe.expect`, native JSON `expect`, Braintrust/Langfuse metadata
  `cloakpipe.expect`) are scored both ways in every run that covers a listed
  suite (each run on its own, never pooled), and the release is blocked
  with `under_blocking`, `over_refusal` or `boundary_incomplete`. Enabling
  the rule requires labelled runs. Policies and runs without these fields
  keep their hashes. See
  `docs/CERTIFICATION.md#two-way-boundary`.
- **MCP tool gate.** `cloakpipe mcp-proxy --manifest ... --certification ...`
  only forwards a `tools/call` when the tool is declared in the release manifest
  and the release's certification verifies at the moment of the call (trusted
  signer, not revoked, unexpired, right environment). Refused calls never reach
  the tool, return JSON-RPC error `-32001` and are recorded in the ledger;
  `--gate warn` forwards and flags instead. Input the gate cannot read is
  refused. ([#14](https://github.com/rohansx/cloakpipe/pull/14))
- **Transparent MCP interceptor.** `cloakpipe mcp-proxy --upstream "<cmd>"` sits
  between an agent and an MCP server, pseudonymizes PII in tool-call arguments
  and rehydrates tokens in tool results, so the tool never sees raw PII.
  ([27889ca](https://github.com/rohansx/cloakpipe/commit/27889ca))
- **Evidence ledger and standalone verifier.** A hash-chained, Ed25519-signed
  evidence ledger that never stores PII, the standalone `cloakpipe-verify` CLI,
  Merkle inclusion proofs, signed auditor manifests and the CloakLeak PII-leak
  benchmark. ([#8](https://github.com/rohansx/cloakpipe/pull/8)) The MCP server
  now records a no-PII ledger hop for each masking call when
  `CLOAKPIPE_LEDGER_DB` is set.
  ([9105613](https://github.com/rohansx/cloakpipe/commit/9105613))
- **Real external anchoring.** `cloakpipe anchor <bundle>` seals a ledger export
  and anchors it at an RFC 3161 timestamp authority and Sigstore Rekor.
  `cloakpipe-verify anchors|all --tsa-root ... --rekor-key ...` checks both fully
  offline and fails closed on missing trust inputs, back-dating and downgraded
  bundles. See `docs/ANCHORING.md`.
  ([#16](https://github.com/rohansx/cloakpipe/pull/16))
- **Release audit packs.** `cloakpipe release audit-pack` assembles one signed
  pack per release (manifest, eval runs, certification, governance events and
  the release-bound ledger slice), and `cloakpipe-verify release-pack` verifies
  it offline with separate trust lists per role. It also rejects a re-signed
  false history, such as a promotion before certification. See
  `docs/AUDIT_PACK.md`. ([#17](https://github.com/rohansx/cloakpipe/pull/17))
- **Anthropic Messages API in the proxy.** `/v1/messages` (and the
  `/v1/anthropic/messages` alias) pseudonymize requests to Anthropic and
  rehydrate responses, including streamed text deltas.
  ([#11](https://github.com/rohansx/cloakpipe/pull/11))
- **Nemotron-v2 PII NER backend**, opt-in alongside the existing backends.
  ([129fa8f](https://github.com/rohansx/cloakpipe/commit/129fa8f))
- **CloakPipe Cloud reporting.** A self-hosted proxy with a `[cloud]` config
  section sends heartbeats and no-PII request telemetry to CloakPipe Cloud.
  ([8d03fd4](https://github.com/rohansx/cloakpipe/commit/8d03fd4),
  [56059ea](https://github.com/rohansx/cloakpipe/commit/56059ea))
- `docker-compose.yml` for one-command self-hosting.
  ([f0fb7e4](https://github.com/rohansx/cloakpipe/commit/f0fb7e4))
- `SECURITY.md` with the vulnerability reporting process.
  ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Changed

- **Breaking (library):** `cloakpipe_mcp::ToolGate::check` takes the call's
  raw arguments (`check(tool, arguments, now)`), and `Denial` has new variants.
  `cloakpipe mcp-proxy` gate configuration errors now exit with the documented
  codes (2 usage, 1 invalid input) instead of 1.
- **Breaking:** format identifiers moved from the legacy `cloakpipe.dev`
  namespace to `cloakpipe.co` (for example `apiVersion: cloakpipe.co/v1alpha1`,
  hash and signing domains, in-toto predicate types and the schema `$id`).
  Writers now emit `cloakpipe.co/...`. Readers and verifiers still accept legacy
  `cloakpipe.dev/v1alpha1` objects, and every hash and signature issued before
  the move stays valid. Because the `apiVersion` and hash domain are part of the
  release hash, a manifest written in the new namespace has a different release
  hash than the same manifest in the legacy namespace; update any pinned hashes
  when you migrate a manifest. ([#19](https://github.com/rohansx/cloakpipe/pull/19))
- Evidence bundles are now v4: the signed manifest commits to the chain tip, so a
  substituted chain of the same length no longer verifies, and
  `cloakpipe-verify all --trust-key` pins the signer. v3 bundles still verify.
  ([#13](https://github.com/rohansx/cloakpipe/pull/13))
- README rewritten around Evaluate, Certify, Enforce, Prove, with every quick-start
  command verified against `main`; `CONTRIBUTING.md` refreshed.
  ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Deprecated

- Langfuse dataset-run import (`--langfuse-run` / `--langfuse-scores`). Langfuse
  removes those endpoints on Langfuse Cloud on 2026-11-16 (self-hosted: v4); use
  `--langfuse-experiment` instead. ([#20](https://github.com/rohansx/cloakpipe/pull/20))

### Removed

- README claims that could not be backed by the code: benchmark, latency and F1
  tables, the competitor comparison, Cloud pricing tiers, the crates.io and
  Docker Hub badges, and the list of `CLOAKPIPE_*` environment variables (most
  are not read by the CLI). ([#18](https://github.com/rohansx/cloakpipe/pull/18))

### Fixed

- Streaming rehydration no longer leaks pseudo-tokens that arrive split across
  SSE chunks, and a token at the very end of a stream is no longer dropped.
  Fixes [#3](https://github.com/rohansx/cloakpipe/issues/3).
  ([1e2ea69](https://github.com/rohansx/cloakpipe/commit/1e2ea69))

## [0.10.0] - 2026-06-04

### Added

- Multi-stage `Dockerfile` and a container config that listens on `0.0.0.0:8900`
  and stores state under `/data`. ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- Release workflow that publishes `ghcr.io/rohansx/cloakpipe` on each version
  tag. ([#7](https://github.com/rohansx/cloakpipe/pull/7))
- Ready-to-use compliance policy configs: `dpdp`, `gdpr`, `hipaa`, `pci-dss` and
  `minimal` (TOML). ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- `Cargo.lock` is committed for reproducible builds.
  ([#5](https://github.com/rohansx/cloakpipe/pull/5))

### Fixed

- Python SDK health check uses the proxy's real `/health` route and default port
  `8900`. ([#5](https://github.com/rohansx/cloakpipe/pull/5))
- Documentation now matches the binary: real CLI subcommands, a working
  build-from-source quick start, the default `127.0.0.1:8900` listen address,
  and the MIT license (previously misstated as Apache-2.0).
  ([#4](https://github.com/rohansx/cloakpipe/pull/4))
- CI is green again (clippy fixes).
  ([#5](https://github.com/rohansx/cloakpipe/pull/5),
  [#6](https://github.com/rohansx/cloakpipe/pull/6))

## [0.9.0] - 2026-03-30

### Added

- DistilBERT-PII NER backend (33 entity types, runs on any CPU).
- nvidia/gliner-PII sidecar support.
- Expanded regex detection patterns.

## [0.8.0] - 2026-03-23

### Added

- Format-preserving pseudonymization: phone numbers, emails, Aadhaar and PAN are
  replaced with fakes of the same format.
- Response scanning: LLM responses are scanned for PII leakage and redacted.
- `cloakpipe scan` to check files and directories for PII before indexing them
  into a vector database.
- LangChain and LlamaIndex packages with drop-in `ChatCloakPipe` and
  `CloakPipeLLM` wrappers.
- Batch detect API in CloakPipe Cloud (`POST /api/detect/batch`, up to 100 texts).
- Compliance policy files for DPDP 2023, GDPR, HIPAA and PCI-DSS.

## [0.7.0] - 2026-03-11

### Added

- Context-aware pseudonymization: session tracking with coreference resolution
  (pronouns, abbreviations, possessives), sensitivity escalation across
  sessions, CLI session commands and an MCP `session_context` tool.
- GLiNER zero-shot NER backend (`backend = "gliner"`): define entity types in
  plain English, no training, pure ONNX Runtime.
- Detection for SSN, Aadhaar, PAN, IPv4, general URLs, natural-language dates,
  `sk-proj`/`sk-live`/`github_pat` secrets and INR/USD/EUR amounts.
- PII benchmark harness (`cargo run -p cloakpipe-core --example pii_benchmark`).
- Admin dashboard with privacy chat, detection feed and compliance views.

### Fixed

- The phone-number pattern no longer matches IP addresses, years or port numbers.

## [0.6.0] - 2026-03-09

### Added

- Fuzzy entity resolution (Jaro-Winkler similarity, prefix matching and
  user-defined alias groups), gated by category so a person and a place with the
  same name are never merged. Works inside the vault with no changes to the
  detection pipeline.

## [0.5.0] - 2026-03-09

### Added

- Industry profiles (`general`, `legal`, `healthcare`, `fintech`) with pre-tuned
  detection settings.
- MCP server with `pseudonymize`, `rehydrate`, `detect`, `vault_stats` and
  `configure` tools.

## [0.4.0] - 2026-03-06

### Added

- ADCPE vector encryption: an orthogonal transform for embedding vectors that
  preserves cosine similarity, with encrypt/decrypt CLI commands.

## [0.3.0] - 2026-03-06

### Added

- SQLite vault and audit backends with per-value AES-256-GCM encryption.
- ONNX BERT-based NER behind the `ner` feature flag.
- Multi-user token scoping.

## [0.2.0] - 2026-03-06

### Added

- CloakTree: vectorless, LLM-driven retrieval for structured documents (PDF and
  Markdown), with parser, tree indexer, search and CLI subcommands.

## [0.1.0] - 2026-03-06

### Added

- First release: privacy middleware for LLM and RAG pipelines.

[Unreleased]: https://github.com/rohansx/cloakpipe/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/rohansx/cloakpipe/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/rohansx/cloakpipe/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/rohansx/cloakpipe/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/rohansx/cloakpipe/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/rohansx/cloakpipe/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/rohansx/cloakpipe/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/rohansx/cloakpipe/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/rohansx/cloakpipe/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/rohansx/cloakpipe/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/rohansx/cloakpipe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/rohansx/cloakpipe/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rohansx/cloakpipe/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rohansx/cloakpipe/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rohansx/cloakpipe/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rohansx/cloakpipe/releases/tag/v0.1.0
