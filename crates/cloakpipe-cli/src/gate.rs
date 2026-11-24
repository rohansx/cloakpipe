//! The MCP tool gate's command line (`cloakpipe mcp-proxy --manifest …`).
//!
//! The gate runs on a single-file v1 manifest (`cloakpipe.manifest.yaml`,
//! detected by its top-level `release` key), whose tool contracts are
//! inline, so `--tool-contract` is refused with it.
//!
//! Deprecated: a legacy Agent Release (top-level `apiVersion`) and the tool
//! contracts it binds (`--tool-contract`). The release is loaded and checked
//! for what the gate reads ([`cloakpipe_release::AgentRelease::gate_issues`]),
//! not for certifiability, so it needs no code, prompt, model or runtime
//! pins; a deprecation warning goes to stderr.
//!
//! A v1 manifest's Cedar policy (`policy:`) is loaded at start-up (an
//! invalid policy refuses to start) with its persistent call counters in
//! `--state-db`, else `$CLOAKPIPE_STATE_DB`, else `$CLOAKPIPE_HOME/state.db`
//! (`CLOAKPIPE_HOME` defaults to `~/.cloakpipe`).
//!
//! Legacy, `certification` cargo feature only (off by default): the
//! `--certification`, `--trust`, `--trust-key`, `--revoked-statement`,
//! `--revoked-key` and `--environment` flags, and a gate that refuses every
//! call unless the release holds a certification that verifies now. Only
//! when one of those flags is given: without them the manifest alone decides.

use crate::keys::{invalid, read, trusted_key, usage, Res};
use crate::manifest::{kind, load_v1, warn_legacy};
use crate::release::load;
use clap::Args;
use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_release::v1::ManifestKind;
use cloakpipe_release::AgentRelease;
use std::path::{Path, PathBuf};

/// Transparently proxy an upstream MCP server. With `--manifest`, only the
/// tools the release declares may be called, with arguments its tool
/// contracts allow (the tool gate). Allowed calls are forwarded unchanged;
/// `--transform pii` masks PII in tool-call arguments and rehydrates
/// pseudonym tokens in results (needs a vault).
#[derive(Debug, Args)]
pub struct McpProxyArgs {
    /// Upstream MCP server command + args, e.g.
    /// --upstream "npx -y @modelcontextprotocol/server-filesystem /data"
    /// (the server named `default`)
    #[arg(long, required_unless_present_any = ["upstream_url", "servers"], conflicts_with = "upstream_url")]
    pub upstream: Option<String>,
    /// Another upstream MCP server, as NAME=COMMAND (repeatable): the gate
    /// starts each, merges their tools/list and routes each tools/call to the
    /// server that serves the tool. A tool name two servers share refuses to
    /// start unless the manifest declares it per server as <server>__<tool>.
    /// Requests other than tools go to the server named `default`
    /// (--upstream), or the only one; else they are refused.
    #[arg(long = "server", value_name = "NAME=COMMAND")]
    pub servers: Vec<String>,
    /// Tools lock (from `cloakpipe tools pin`): a tool whose definition does
    /// not match its pin, or that has none, is hidden from tools/list and
    /// refused (tool_drift). Without it, a tool whose definition changes
    /// during the session is.
    #[arg(long = "tools-lock")]
    pub tools_lock: Option<PathBuf>,
    /// Upstream MCP server over Streamable HTTP, e.g.
    /// --upstream-url https://tools.example.com/mcp (instead of --upstream;
    /// not with --server or --tools-lock yet).
    #[arg(long = "upstream-url", value_name = "URL", conflicts_with_all = ["servers", "tools_lock"])]
    pub upstream_url: Option<String>,
    /// Header sent on every request to --upstream-url (repeatable), as
    /// 'Name: value'; a value `env:VAR` is read from that environment
    /// variable, e.g. 'Authorization: env:TOOLS_AUTH'. Values are never
    /// logged.
    #[arg(long = "upstream-header", value_name = "NAME: VALUE", requires = "upstream_url")]
    pub upstream_headers: Vec<String>,
    /// Serve MCP over HTTP (Streamable HTTP, POST /mcp) on this address
    /// instead of stdio, e.g. 127.0.0.1:8900 (port 0 picks one; the bound
    /// address is printed on stderr). GET /health reports the release.
    /// Bind a non-loopback address only with --listen-token-file.
    #[arg(long, value_name = "ADDR")]
    pub listen: Option<String>,
    /// File holding a bearer token every /mcp request must carry
    /// (Authorization: Bearer <token>).
    #[arg(long = "listen-token-file", value_name = "FILE", requires = "listen")]
    pub listen_token_file: Option<PathBuf>,
    /// Manifest the agent runs under (cloakpipe.manifest.yaml; a legacy
    /// Agent Release is deprecated). Enables the tool gate: tools/call must
    /// name a tool the manifest declares, with arguments it allows.
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// DSSE certification envelope of the release. Without one, every
    /// tools/call is refused (enforce) or reported (warn).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub certification: Option<PathBuf>,
    /// Trusted signer key file (from `release keygen`; public part only).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub trust: Vec<PathBuf>,
    /// Trusted signer as KEYID=PUBHEX.
    #[cfg(feature = "certification")]
    #[arg(long = "trust-key")]
    pub trust_keys: Vec<String>,
    /// sha256 hex of a revoked certification statement.
    #[cfg(feature = "certification")]
    #[arg(long = "revoked-statement")]
    pub revoked_statements: Vec<String>,
    /// Key id of a revoked signer.
    #[cfg(feature = "certification")]
    #[arg(long = "revoked-key")]
    pub revoked_keys: Vec<String>,
    /// Environment the agent runs in; the certification must cover it
    /// (default: production).
    #[cfg(feature = "certification")]
    #[arg(long)]
    pub environment: Option<String>,
    /// enforce (default): refuse calls that fail the gate; shadow: forward
    /// every call the gate can read, and record what enforce would have
    /// decided (entries marked `mode: shadow`).
    #[arg(long, value_parser = ["enforce", "shadow"])]
    pub mode: Option<String>,
    /// Old name of --mode (warn = shadow).
    #[arg(long, hide = true, value_parser = ["enforce", "warn"], conflicts_with = "mode")]
    pub gate: Option<String>,
    /// The decision ledger every gate decision is appended to, signed.
    #[command(flatten)]
    pub ledger: crate::evidence::LedgerArgs,
    /// Scheduled anchoring of the decision ledger (epochs, RFC 3161, Rekor).
    #[command(flatten)]
    pub anchoring: crate::evidence::AnchoringArgs,
    /// Where gate events go: a JSONL log, webhooks, OpenTelemetry.
    #[command(flatten)]
    pub events: crate::events::EventArgs,
    /// Legacy Agent Release only (deprecated; a v1 manifest declares its
    /// contracts inline). Tool contract (repeatable): argument-level rules
    /// for the tools it covers. Each must be bound by the release (`spec.policies` entry
    /// `policy:tool-contract/<name>@sha256:<digest>`), and every contract the
    /// release binds must be supplied, or the proxy refuses to start.
    #[arg(long = "tool-contract")]
    pub tool_contracts: Vec<PathBuf>,
    /// Trusted task context: a JSON object written by the orchestrator, e.g.
    /// {"taskId":"t-981","ticket":{"id":"T-1042"}}. `one_of_context` (legacy:
    /// `bindTo: task.<key>`) arguments must equal its values. Default:
    /// $CLOAKPIPE_TASK_CONTEXT.
    #[arg(long = "task-context")]
    pub task_context: Option<PathBuf>,
    /// Directory of approval receipts (`<fingerprint hex>.approval.json`, from
    /// `cloakpipe approve`) for calls that need approval (`approval:` in the
    /// manifest; legacy: requiresApproval).
    /// Needs --approver-key.
    #[arg(long)]
    pub approvals: Option<PathBuf>,
    /// Approver key file (repeatable; from `release keygen`, public part
    /// only): receipts must be signed by one of these keys.
    #[arg(long = "approver-key")]
    pub approver_keys: Vec<PathBuf>,
    /// An approval broker the gate files requests with and fetches
    /// verified receipts from (--approvals-url, docs/APPROVALS.md).
    #[command(flatten)]
    pub broker: crate::approvals::BrokerArgs,
    /// Operations database (SQLite) tracking side-effecting calls (tools with
    /// side_effect: true; legacy: sideEffect): required when there are any.
    /// Default: $CLOAKPIPE_OPERATIONS_DB. One proxy per database.
    #[arg(long = "operations-db")]
    pub operations_db: Option<PathBuf>,
    /// State database (SQLite) for the Cedar policy's persistent call
    /// counters (context.counters), used when the manifest has `policy:`.
    /// Default: $CLOAKPIPE_STATE_DB, else $CLOAKPIPE_HOME/state.db
    /// (CLOAKPIPE_HOME defaults to ~/.cloakpipe). The counters survive a
    /// restart, so a rate limit cannot be reset by restarting the proxy.
    #[arg(long = "state-db")]
    pub state_db: Option<PathBuf>,
    /// Opt-in transform of allowed calls. `pii`: pseudonymize PII in
    /// tool-call arguments before the tool sees them and rehydrate tokens in
    /// results, through the vault (CLOAKPIPE_VAULT_KEY, vault.path in the
    /// config). Default: none; arguments reach the tool as the agent sent
    /// them and no vault is used.
    #[arg(long, value_parser = ["pii"])]
    pub transform: Option<String>,
    /// Record every tools/call (raw arguments), tools/list reply and the task
    /// context to a local JSONL file in this directory, for `cloakpipe
    /// infer`. Shadow mode (or no --manifest) only. Owner-only files, never
    /// sent anywhere.
    #[arg(long, value_name = "DIR")]
    pub capture: Option<PathBuf>,
    /// With --capture: keep only the shape of each string (length, pattern
    /// class, salted hash), never its value.
    #[arg(long = "capture-shapes", requires = "capture")]
    pub capture_shapes: bool,
    /// With --capture: first delete capture files older than this many days.
    #[arg(long = "capture-max-age", value_name = "DAYS", requires = "capture")]
    pub capture_max_age: Option<u64>,
}

impl McpProxyArgs {
    /// Whether `--transform pii` was given.
    pub fn pii(&self) -> bool {
        self.transform.as_deref() == Some("pii")
    }

    /// Whether any gate flag is set: without `--manifest`, that would
    /// silently run ungated.
    /// Whether any legacy certification flag is set. The certification gate
    /// is opt-in: without one, the manifest alone decides.
    fn any_certification_flag(&self) -> bool {
        #[cfg(feature = "certification")]
        return self.certification.is_some()
            || !self.trust.is_empty()
            || !self.trust_keys.is_empty()
            || !self.revoked_statements.is_empty()
            || !self.revoked_keys.is_empty()
            || self.environment.is_some();
        #[cfg(not(feature = "certification"))]
        false
    }

    fn any_gate_flag(&self) -> bool {
        self.any_certification_flag()
            || self.gate.is_some()
            || self.mode.is_some()
            || self.ledger.signing_key.is_some()
            || self.anchoring.any()
            || self.events.any()
            || !self.tool_contracts.is_empty()
            // A capture records the task context without a gate.
            || (self.task_context.is_some() && self.capture.is_none())
            || self.approvals.is_some()
            || !self.approver_keys.is_empty()
            || self.broker.any()
            || self.operations_db.is_some()
            || self.state_db.is_some()
    }
}

/// Load the release the gate runs on and check what the gate reads from it.
/// Issues go to stderr.
fn load_release(path: &Path) -> Res<AgentRelease> {
    let release = load(path)?;
    let issues = release.gate_issues();
    if issues.is_empty() {
        return Ok(release);
    }
    for i in &issues {
        eprintln!("error: {}: {i}", path.display());
    }
    Err(invalid("the tool gate cannot run on this release"))
}

/// Build the tool gate for `mcp-proxy`; `Ok(None)` without `--manifest`.
/// Problems are reported on stderr.
pub(crate) fn gate_from_args(a: &McpProxyArgs) -> Res<Option<cloakpipe_mcp::ToolGate>> {
    // Raw arguments are captured only where nothing is enforced.
    let shadow = a.mode.as_deref() == Some("shadow") || a.gate.as_deref() == Some("warn");
    if a.capture.is_some() && a.manifest.is_some() && !shadow {
        return Err(usage(CAPTURE_SHADOW_ONLY));
    }
    let Some(manifest_path) = &a.manifest else {
        if a.any_gate_flag() {
            return Err(usage("release gate flags need --manifest (the release they are about)"));
        }
        return Ok(None);
    };
    let mode = match (a.mode.as_deref(), a.gate.as_deref()) {
        (Some("shadow"), _) | (_, Some("warn")) => cloakpipe_mcp::GateMode::Shadow,
        _ => cloakpipe_mcp::GateMode::Enforce,
    };
    let gate = match kind(manifest_path)? {
        ManifestKind::V1 => {
            if !a.tool_contracts.is_empty() {
                return Err(usage(format_args!(
                    "--tool-contract is for the legacy AgentRelease format: {} is a v1 manifest, whose tool contracts are inline",
                    manifest_path.display()
                )));
            }
            let manifest = load_v1(manifest_path)?;
            let task = task_context(a)?;
            cloakpipe_mcp::ToolGate::from_manifest(mode, &manifest).with_task_context(task).map_err(usage)?
        }
        ManifestKind::Legacy => {
            warn_legacy(manifest_path);
            let manifest = load_release(manifest_path)?;
            let mut contracts = Vec::new();
            for p in &a.tool_contracts {
                let contract = cloakpipe_release::contract::ToolContract::parse_path(p).map_err(|e| match e {
                    cloakpipe_release::contract::ContractError::Io(..) => usage(format_args!("--tool-contract: {e}")),
                    _ => invalid(format_args!("--tool-contract {}: {e}", p.display())),
                })?;
                contracts.push(contract);
            }
            let task = task_context(a)?;
            // Refuse to start unless the contracts are exactly the ones the release binds.
            cloakpipe_mcp::ToolGate::new(mode, &manifest).with_contracts(contracts, task).map_err(usage)?
        }
    };
    #[cfg(feature = "certification")]
    let gate = if a.any_certification_flag() {
        let certification = legacy::certification(a)?;
        gate.with_certification(&certification.environment, certification.envelope, certification.verify)
    } else {
        gate
    };
    let approvals = approvals(a)?;
    let mut gate = gate;
    if let Some((dir, approvers)) = approvals {
        gate = gate.with_approvals(dir, approvers);
    }
    let operations_db = a
        .operations_db
        .clone()
        .or_else(|| std::env::var_os("CLOAKPIPE_OPERATIONS_DB").filter(|v| !v.is_empty()).map(PathBuf::from));
    if let Some(path) = operations_db {
        let store = cloakpipe_mcp::operations::OperationStore::open(&path)
            .map_err(|e| usage(format_args!("--operations-db {}: {e}", path.display())))?;
        gate = gate.with_operations(store).map_err(usage)?;
        for op in gate.recovered_operations() {
            eprintln!("warning: operation {op} was left in flight by a previous run: its outcome is unknown until reconciled (cloakpipe operations reconcile)");
        }
    }
    if gate.has_policy() {
        let path = state_db(a)?;
        let counters = cloakpipe_mcp::Counters::open(&path)
            .map_err(|e| usage(format_args!("--state-db {}: {e}", path.display())))?;
        gate = gate.with_policy(counters).map_err(invalid)?;
        eprintln!(
            "cloakpipe: Cedar policy {} loaded ({} policies); call counters in {}",
            gate.policy_digest().unwrap_or_default(),
            gate.policy_ids().len(),
            path.display()
        );
    }
    // A side-effect tool with no operations store, or a policy not loaded, must not run.
    gate.ready().map_err(usage)?;
    Ok(Some(gate))
}

/// Legacy (`certification` feature): the certification flags.
#[cfg(feature = "certification")]
mod legacy {
    use super::McpProxyArgs;
    use crate::keys::{inline_key, invalid, read, trusted_key, usage, Res};
    use cloakpipe_cert::statement::{Envelope, VerifyContext};
    use std::collections::BTreeSet;

    pub(super) struct Certification {
        pub environment: String,
        pub envelope: Option<Envelope>,
        pub verify: VerifyContext,
    }

    pub(super) fn certification(a: &McpProxyArgs) -> Res<Certification> {
        let mut revoked_statements = BTreeSet::new();
        for d in &a.revoked_statements {
            let hex = d.trim().trim_start_matches("sha256:").to_ascii_lowercase();
            if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(usage(format_args!("--revoked-statement {d:?}: expected a sha256 hex digest")));
            }
            revoked_statements.insert(hex);
        }
        let mut trusted = a.trust_keys.iter().map(|k| inline_key(k)).collect::<Res<Vec<_>>>()?;
        for p in &a.trust {
            trusted.push(trusted_key(p)?);
        }
        let envelope = match &a.certification {
            None => {
                eprintln!("warning: no --certification: every tools/call fails the release gate");
                None
            }
            Some(p) => {
                if trusted.is_empty() {
                    eprintln!("warning: no trusted keys (--trust / --trust-key); the certification cannot verify");
                }
                let src = read(p)?;
                Some(
                    serde_json::from_str::<Envelope>(&src)
                        .map_err(|e| invalid(format_args!("{}: not a DSSE envelope: {e}", p.display())))?,
                )
            }
        };
        let verify = VerifyContext {
            trusted,
            revoked_statements,
            revoked_keys: a.revoked_keys.iter().cloned().collect(),
            ..Default::default()
        };
        let environment = a.environment.as_deref().unwrap_or("production").to_string();
        Ok(Certification { environment, envelope, verify })
    }
}

/// `--approvals` with its `--approver-key`s: both or neither, and the
/// directory must exist.
fn approvals(a: &McpProxyArgs) -> Res<Option<(PathBuf, Vec<TrustedKey>)>> {
    match (&a.approvals, a.approver_keys.is_empty()) {
        (None, true) => Ok(None),
        (None, false) => Err(usage("--approver-key needs --approvals (the receipts it verifies)")),
        (Some(_), true) => Err(usage("--approvals needs at least one --approver-key (who may approve)")),
        (Some(dir), false) => {
            if !dir.is_dir() {
                return Err(usage(format_args!("--approvals {}: not a directory", dir.display())));
            }
            let keys = a.approver_keys.iter().map(|p| trusted_key(p)).collect::<Res<Vec<_>>>()?;
            Ok(Some((dir.clone(), keys)))
        }
    }
}

/// Where the policy counters live: `--state-db`, `$CLOAKPIPE_STATE_DB`, or
/// `$CLOAKPIPE_HOME/state.db` (the directory is created, owner-only).
fn state_db(a: &McpProxyArgs) -> Res<PathBuf> {
    if let Some(p) = a.state_db.clone().or_else(|| std::env::var_os("CLOAKPIPE_STATE_DB").filter(|v| !v.is_empty()).map(PathBuf::from)) {
        return Ok(p);
    }
    let home = cloakpipe_home().ok_or_else(|| usage("cannot find a home directory for the state database: set --state-db or CLOAKPIPE_HOME"))?;
    create_private_dir(&home).map_err(|e| usage(format_args!("--state-db: cannot create {}: {e}", home.display())))?;
    Ok(home.join("state.db"))
}

/// `$CLOAKPIPE_HOME`, else `~/.cloakpipe`.
pub(crate) fn cloakpipe_home() -> Option<PathBuf> {
    if let Some(h) = std::env::var_os("CLOAKPIPE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(h));
    }
    std::env::var_os("HOME").filter(|v| !v.is_empty()).map(|h| PathBuf::from(h).join(".cloakpipe"))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(dir)
}

/// The upstreams `mcp-proxy` fronts: `--upstream` (a stdio command, the
/// server named `default`) and `--server NAME=COMMAND`s, or `--upstream-url`
/// with its `--upstream-header`s (`env:VAR` values read now, so a missing
/// variable fails before anything starts).
pub(crate) fn upstreams_from_args(a: &McpProxyArgs) -> Res<Vec<cloakpipe_mcp::Upstream>> {
    let name = cloakpipe_mcp::DEFAULT_SERVER;
    let Some(url) = &a.upstream_url else {
        // Checked here too (clap's `requires` let it through): a credential
        // meant for an HTTP upstream is never silently dropped.
        if !a.upstream_headers.is_empty() {
            return Err(usage("--upstream-header needs --upstream-url (the HTTP upstream it is sent to)"));
        }
        return crate::tools::upstreams(a.upstream.as_deref(), &a.servers);
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(usage("--upstream-url must be an http:// or https:// URL"));
    }
    let mut headers = Vec::new();
    for h in &a.upstream_headers {
        let Some((name, value)) = h.split_once(':') else {
            return Err(usage(format_args!("--upstream-header {h:?}: expected 'Name: value'")));
        };
        let name = name.trim();
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
            return Err(usage(format_args!("--upstream-header: {name:?} is not a header name")));
        }
        let value = value.trim();
        let value = match value.strip_prefix("env:") {
            Some(var) => std::env::var(var)
                .map_err(|_| usage(format_args!("--upstream-header {name}: environment variable {var} is not set")))?,
            None => value.to_string(),
        };
        headers.push((name.to_string(), value));
    }
    Ok(vec![cloakpipe_mcp::Upstream::http(name, url.clone(), headers)])
}

const CAPTURE_SHADOW_ONLY: &str = "--capture is only available in shadow mode (--mode shadow) or without --manifest";

/// `--capture`: `Ok(None)` without it. Raw arguments are recorded only
/// where nothing is enforced: in shadow mode, or without a gate.
pub(crate) fn capture_from_args(a: &McpProxyArgs, gate: Option<&cloakpipe_mcp::ToolGate>) -> Res<Option<cloakpipe_mcp::Capture>> {
    let Some(dir) = &a.capture else { return Ok(None) };
    if gate.is_some_and(|g| g.mode == cloakpipe_mcp::GateMode::Enforce) {
        return Err(usage(CAPTURE_SHADOW_ONLY));
    }
    if let Some(days) = a.capture_max_age {
        let n = cloakpipe_mcp::capture::prune(dir, std::time::Duration::from_secs(days.saturating_mul(86_400)))
            .map_err(|e| usage(format_args!("--capture {}: {e}", dir.display())))?;
        if n > 0 {
            eprintln!("cloakpipe: deleted {n} capture file(s) older than {days} days");
        }
    }
    let task = task_context(a)?;
    let capture = cloakpipe_mcp::Capture::open(dir, task.as_ref(), a.capture_shapes)
        .map_err(|e| usage(format_args!("--capture {}: {e}", dir.display())))?;
    eprintln!("cloakpipe: capturing tool calls to {} (local only; delete it after `cloakpipe infer`)", capture.path().display());
    Ok(Some(capture))
}

/// `--listen` with its token: `Ok(None)` without `--listen`.
pub(crate) fn listen_from_args(a: &McpProxyArgs) -> Res<Option<cloakpipe_mcp::ListenConfig>> {
    let Some(listen) = &a.listen else { return Ok(None) };
    let addr = std::net::ToSocketAddrs::to_socket_addrs(listen.as_str())
        .ok()
        .and_then(|mut addrs| addrs.next())
        .ok_or_else(|| usage(format_args!("--listen {listen:?}: expected HOST:PORT, e.g. 127.0.0.1:8900")))?;
    let token = match &a.listen_token_file {
        Some(path) => {
            let token = read(path)?.trim().to_string();
            if token.is_empty() {
                return Err(usage(format_args!("--listen-token-file {}: the file is empty", path.display())));
            }
            Some(token)
        }
        None => None,
    };
    Ok(Some(cloakpipe_mcp::ListenConfig { addr, token }))
}

/// The trusted task context: `--task-context`, else `$CLOAKPIPE_TASK_CONTEXT`.
/// It comes only from the operator, never from MCP messages.
fn task_context(a: &McpProxyArgs) -> Res<Option<serde_json::Value>> {
    let path = a
        .task_context
        .clone()
        .or_else(|| std::env::var_os("CLOAKPIPE_TASK_CONTEXT").filter(|v| !v.is_empty()).map(PathBuf::from));
    let Some(path) = path else { return Ok(None) };
    let src = read(&path)?;
    let task: serde_json::Value = serde_json::from_str(&src)
        .map_err(|e| invalid(format_args!("task context {}: not JSON: {e}", path.display())))?;
    if !task.is_object() {
        return Err(invalid(format_args!("task context {}: must be a JSON object", path.display())));
    }
    Ok(Some(task))
}
