//! Runtime tool gate (Phase C): may this Agent Release call this tool now?
//!
//! The gate runs on a single-file v1 manifest ([`ToolGate::from_manifest`],
//! `cloakpipe.manifest.yaml`, see [`cloakpipe_release::v1`]) or, deprecated,
//! on a legacy AgentRelease plus the ToolContracts it binds
//! ([`ToolGate::new`] + [`ToolGate::with_contracts`]). Both compile to the
//! same per-tool rules. With a v1 manifest every declared tool has rules
//! (closed by default: a tool without `args` takes no arguments); a
//! side-effecting tool's operation id comes from its `idempotency_key`
//! template when it has one, and approval can be conditional (`when`), routed
//! (`approvers`, reported in [`ToolGate::approval_request`]) and bounded
//! (`ttl`: a receipt valid for longer than that is `approval_invalid`).
//!
//! The MCP interceptor asks [`ToolGate::check`] before forwarding each
//! `tools/call`. A call is allowed only when the tool is declared in the
//! release manifest (`spec.tools`, by name: `tool:refund@4` declares
//! `refund`) and passes the tool contract that covers it, if any (below).
//! `shadow` mode reaches the same verdicts but lets calls through.
//!
//! Legacy, `certification` cargo feature only (off by default):
//! [`ToolGate::with_certification`] also requires the release to hold a
//! certification that verifies offline *now* (`cloakpipe_cert::statement::verify`:
//! trusted signer, not revoked, inside its validity window, about this
//! release, `certified` decision) for the gate's environment; without one
//! every call is refused.
//!
//! A release can also bind tool contracts (`policy:tool-contract/...` in
//! `spec.policies`, see [`cloakpipe_release::contract`]). The gate is then
//! given the contracts and the trusted task context with
//! [`ToolGate::with_contracts`], which refuses a contract the release does
//! not bind and a bound contract that was not supplied. For a tool a
//! contract covers, [`ToolGate::check`] also validates the call's raw
//! (pre-masking) arguments. Declared tools no contract covers keep the
//! behaviour above.
//!
//! A contract tool with `requiresApproval: true` also needs a signed
//! approval receipt for this exact call ([`cloakpipe_receipt::approval`]): the
//! gate computes the call's fingerprint
//! ([`cloakpipe_release::action::fingerprint`] over the raw arguments),
//! reads `<fingerprint hex>.approval.json` from the directory given to
//! [`ToolGate::with_approvals`] and verifies it against the release, the
//! tool, the task context's `taskId` and the trusted approver keys.
//! [`ToolGate::authorize`] returns the receipt's digest and operation id so
//! the call can be recorded against it.
//!
//! A contract tool with `sideEffect: true` is an *operation*
//! ([`crate::operations`]): [`ToolGate::authorize`] names it (the receipt's
//! `operationId`, else [`derive_operation_id`], keyed by the store, from the task context's
//! `taskId` and the call fingerprint) and the interceptor runs it through
//! the operations store given to [`ToolGate::with_operations`], so a call
//! whose outcome is unknown is never silently re-executed. A gate with such
//! a tool and no store is not [`ToolGate::ready`].
//!
//! A v1 manifest may reference a Cedar policy (`policy:`, see
//! [`cloakpipe_policy`]). [`ToolGate::with_policy`] parses it (an invalid
//! policy refuses to start) and gives it the persistent call counters; until
//! then the gate is not [`ToolGate::ready`] and refuses every call as
//! `fail_closed`. The decision order is contract -> Cedar -> approval: a
//! call that passes its contract is evaluated with Cedar (no satisfied
//! permit, or a satisfied forbid: `policy_denied`, with the satisfied
//! forbids' ids; any evaluation error: `fail_closed`), and needs an approval
//! receipt when the manifest's `approval:` rule holds *or* every satisfied
//! permit carries `@approval("<route>")` (its routes join the manifest's
//! `approvers`). Without `policy:`, Cedar is skipped. The interceptor
//! counts each call it forwards ([`ToolGate::record_forwarded`]) for the
//! policy's `context.counters`.
//!
//! With an approval broker ([`Self::with_broker`], [`crate::broker`]), a
//! call refused as `approval_required` is also filed with the broker
//! ([`ToolGate::request_approval`]), off the decision path; the broker's
//! poller writes verified receipts into the approvals directory. A call an
//! approver denied is refused as `approval_denied` while the denial holds
//! (the broker's memory, or a `<fingerprint hex>.denied.json` marker in the
//! approvals directory, which is honoured with or without a broker).

#[cfg(feature = "certification")]
use cloakpipe_cert::statement::{verify, Status, VerifyContext};
use cloakpipe_policy::{CallInput, Counters, PolicyDecision, PolicyEngine, PolicyError};
use cloakpipe_receipt::approval::{verify_approval, ApprovalCheck, ApprovalError};
use cloakpipe_receipt::dsse::{Envelope, TrustedKey};
use cloakpipe_receipt::dsse::parse_rfc3339;
use cloakpipe_release::action::{derive_idempotent_operation_id, derive_operation_id, fingerprint, ToolCallFingerprint};
use cloakpipe_release::contract::{self, ToolContract, ToolRule, ViolationCode};
use cloakpipe_release::v1::Manifest;
use cloakpipe_release::{AgentRelease, Reference, ReleaseHash};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::broker::{denial_in_force, ApprovalBroker, BrokerRequest, RequestStatus};
use crate::operations::OperationStore;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateMode {
    /// Refuse calls that fail the gate.
    Enforce,
    /// Forward them, recording what enforce mode would have decided
    /// (`--mode shadow`; `--gate warn` is the old name).
    Shadow,
}

/// Why a call fails the gate. `code()` is stable and safe to record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denial {
    /// The manifest does not declare this tool.
    UndeclaredTool,
    /// Legacy (`certification` feature): no certification was supplied.
    #[cfg(feature = "certification")]
    Uncertified,
    /// Legacy (`certification` feature): the certification does not certify
    /// the release now; carries the verification status (`expired`,
    /// `revoked`, `invalid`, ...) or `blocked` for a verified BLOCKED decision.
    #[cfg(feature = "certification")]
    NotCertified(String),
    /// Legacy (`certification` feature): certified, but for another environment.
    #[cfg(feature = "certification")]
    WrongEnvironment(String),
    /// A required argument is absent (`path`: its contract path).
    ArgumentMissing { path: Option<String> },
    /// An argument the manifest does not declare. Its name is never reported;
    /// `path` is the object holding it (`None` at the top level).
    UndeclaredArgument { path: Option<String> },
    /// A value breaks its constraint (`path`: the contract path, never the value).
    ArgumentInvalid { path: Option<String> },
    /// A `bindTo` argument differs from the trusted task context.
    ScopeMismatch { path: Option<String> },
    /// A `bindTo` argument needs a task context (key) the gate does not have.
    TaskContextMissing { path: Option<String> },
    /// The contract requires an approval receipt for this call and there is
    /// none (any change to the arguments is a different call).
    ApprovalRequired,
    /// The receipt for this call is malformed, not signed by a trusted
    /// approver, or for another release, tool, task or call.
    ApprovalInvalid,
    /// The receipt for this call has passed its `notAfter`.
    ApprovalExpired,
    /// An approver denied this exact call (an approval broker's decision,
    /// or a denial marker), and the denial still holds.
    ApprovalDenied,
    /// The release binds a tool contract the gate was not given.
    ContractMissing,
    /// The operation id names a different call (operations store).
    OperationConflict { operation_id: String },
    /// The operation is in flight or its outcome is unknown: an operator
    /// must reconcile it (`cloakpipe operations reconcile`) before a retry.
    ReconcileBeforeRetry { operation_id: String },
    /// The operations store could not be read or written.
    OperationsUnavailable,
    /// A side-effecting call sent as a notification (no JSON-RPC id): its
    /// outcome could never be settled.
    RequestIdMissing,
    /// A side-effecting call reusing the JSON-RPC id of a call still in
    /// flight: the replies could not be told apart.
    RequestIdInUse,
    /// The Cedar policy refuses the call: no permit holds, or a forbid does
    /// (`policies`: the satisfied forbids' ids, from the policy file).
    PolicyDenied { policies: Vec<String> },
    /// A gate stage could not decide (a Cedar evaluation error, the counter
    /// store failing, a policy not loaded): the call is refused.
    FailClosed,
    /// The tool's definition on `server` no longer matches its pin in the
    /// tools lock (or has none), or changed during the session: hidden from
    /// the agent and refused until the gate restarts. Refused in shadow mode
    /// too.
    ToolDrift { server: String },
    /// No upstream server serves this tool (several servers): refused in
    /// shadow mode too, as there is nowhere to send it.
    ToolUnavailable,
}

impl Denial {
    pub fn code(&self) -> String {
        match self {
            Denial::UndeclaredTool => "undeclared_tool".into(),
            #[cfg(feature = "certification")]
            Denial::Uncertified => "uncertified".into(),
            #[cfg(feature = "certification")]
            Denial::NotCertified(status) => status.clone(),
            #[cfg(feature = "certification")]
            Denial::WrongEnvironment(_) => "wrong_environment".into(),
            Denial::ArgumentMissing { .. } => ViolationCode::ArgumentMissing.code().into(),
            Denial::UndeclaredArgument { .. } => ViolationCode::UndeclaredArgument.code().into(),
            Denial::ArgumentInvalid { .. } => ViolationCode::ArgumentInvalid.code().into(),
            Denial::ScopeMismatch { .. } => ViolationCode::ScopeMismatch.code().into(),
            Denial::TaskContextMissing { .. } => ViolationCode::TaskContextMissing.code().into(),
            Denial::ApprovalRequired => "approval_required".into(),
            Denial::ApprovalInvalid => "approval_invalid".into(),
            Denial::ApprovalExpired => "approval_expired".into(),
            Denial::ApprovalDenied => "approval_denied".into(),
            Denial::ContractMissing => "contract_missing".into(),
            Denial::OperationConflict { .. } => "operation_conflict".into(),
            Denial::ReconcileBeforeRetry { .. } => "reconcile_before_retry".into(),
            Denial::OperationsUnavailable => "operations_unavailable".into(),
            Denial::RequestIdMissing => "request_id_missing".into(),
            Denial::RequestIdInUse => "request_id_in_use".into(),
            Denial::PolicyDenied { .. } => "policy_denied".into(),
            Denial::FailClosed => "fail_closed".into(),
            Denial::ToolDrift { .. } => "tool_drift".into(),
            Denial::ToolUnavailable => "tool_unavailable".into(),
        }
    }

    /// The upstream server a `tool_drift` is about.
    pub fn server(&self) -> Option<&str> {
        match self {
            Denial::ToolDrift { server } => Some(server),
            _ => None,
        }
    }

    /// Whether the refusal is about the upstream servers' tools rather than
    /// the release (`tool_drift`, `tool_unavailable`): it holds in shadow
    /// mode too.
    pub fn is_upstream(&self) -> bool {
        matches!(self, Denial::ToolDrift { .. } | Denial::ToolUnavailable)
    }

    /// The operation an operations-store denial is about.
    pub fn operation_id(&self) -> Option<&str> {
        match self {
            Denial::OperationConflict { operation_id } | Denial::ReconcileBeforeRetry { operation_id } => Some(operation_id),
            _ => None,
        }
    }

    /// The policies that determined a `policy_denied` (ids from the policy
    /// file, so safe to record).
    pub fn policies(&self) -> Option<&[String]> {
        match self {
            Denial::PolicyDenied { policies } => Some(policies),
            _ => None,
        }
    }

    /// The contract path of an argument denial: built from contract names,
    /// so safe to record (as `gate_path`).
    pub fn path(&self) -> Option<&str> {
        match self {
            Denial::ArgumentMissing { path }
            | Denial::UndeclaredArgument { path }
            | Denial::ArgumentInvalid { path }
            | Denial::ScopeMismatch { path }
            | Denial::TaskContextMissing { path } => path.as_deref(),
            _ => None,
        }
    }
}

impl From<contract::Violation> for Denial {
    fn from(v: contract::Violation) -> Self {
        let path = v.path;
        match v.code {
            ViolationCode::ArgumentMissing => Denial::ArgumentMissing { path },
            ViolationCode::UndeclaredArgument => Denial::UndeclaredArgument { path },
            ViolationCode::ArgumentInvalid => Denial::ArgumentInvalid { path },
            ViolationCode::ScopeMismatch => Denial::ScopeMismatch { path },
            ViolationCode::TaskContextMissing => Denial::TaskContextMissing { path },
        }
    }
}

/// A call the gate let through on the strength of an approval receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedCall {
    /// SHA-256 of the receipt file's bytes: what the ledger records
    /// (`approval`), so an auditor holding the receipt can match it.
    pub receipt_digest: [u8; 32],
    /// The receipt's `operationId`.
    pub operation_id: String,
    /// The call's fingerprint (operator state; never recorded in the ledger).
    pub fingerprint: ToolCallFingerprint,
}

/// The operation a side-effecting call is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationKey {
    /// The approval receipt's `operationId`, else the derived id.
    pub operation_id: String,
    /// The call's fingerprint: the store's `call_digest` (never ledger content).
    pub fingerprint: ToolCallFingerprint,
}

/// What the gate establishes about an allowed call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Authorization {
    /// Set when the call needed, and has, a valid approval receipt.
    pub approval: Option<ApprovedCall>,
    /// Set when the contract marks the tool `sideEffect: true`.
    pub operation: Option<OperationKey>,
}

/// What an external approval broker needs to route a request for a call
/// the gate refused as `approval_required`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// The tool's `approval.approvers` routes (empty for a legacy contract).
    pub approvers: Vec<String>,
    /// The call's fingerprint (`sha256:<hex>`): what a receipt must cover.
    pub fingerprint: String,
}

/// Where approval receipts come from and who may sign them.
struct Approvals {
    dir: PathBuf,
    approvers: Vec<TrustedKey>,
}

/// Why a gate cannot start with the given contracts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateConfigError {
    /// A supplied contract whose reference is not in `spec.policies`.
    NotInRelease { policy_ref: String },
    /// A contract the release binds that was not supplied.
    NotSupplied { policy_ref: String },
    /// Two supplied contracts cover the same tool.
    AmbiguousTool { tool: String },
    /// A contract tool with `sideEffect: true` and no operations store.
    OperationsRequired { tool: String },
    /// The operations store could not be prepared.
    OperationsStore(String),
    /// The task context is not a JSON object.
    TaskContextNotObject,
    /// The manifest's Cedar policy is invalid.
    Policy(String),
    /// The manifest references a Cedar policy that was not loaded
    /// ([`ToolGate::with_policy`]).
    PolicyNotLoaded,
}

impl std::fmt::Display for GateConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GateConfigError::NotInRelease { policy_ref } => write!(
                f,
                "tool contract {policy_ref} is not bound by the release: add it to spec.policies or supply the contract the release binds"
            ),
            GateConfigError::NotSupplied { policy_ref } => {
                write!(f, "the release binds tool contract {policy_ref}, which was not supplied (--tool-contract)")
            }
            GateConfigError::AmbiguousTool { tool } => write!(f, "more than one tool contract covers tool {tool:?}"),
            GateConfigError::OperationsRequired { tool } => write!(
                f,
                "tool {tool:?} has sideEffect: true: its operations must be tracked in an operations store (--operations-db or CLOAKPIPE_OPERATIONS_DB)"
            ),
            GateConfigError::OperationsStore(e) => write!(f, "operations store: {e}"),
            GateConfigError::TaskContextNotObject => write!(f, "the task context must be a JSON object"),
            GateConfigError::Policy(e) => write!(f, "{e}"),
            GateConfigError::PolicyNotLoaded => {
                write!(f, "the manifest references a Cedar policy, which was not loaded with its counter store")
            }
        }
    }
}

impl std::error::Error for GateConfigError {}

/// The manifest's Cedar policy and the counters it reads.
struct PolicyState {
    engine: PolicyEngine,
    counters: Mutex<Counters>,
}

/// What Cedar said about a call that passed its contract.
enum PolicyVerdict {
    /// No policy, or a plain permit.
    Allow,
    /// Every satisfied permit carries `@approval`; these are the routes.
    RequireApproval(Vec<String>),
}

/// Legacy (`certification` feature): the certification a gate requires.
#[cfg(feature = "certification")]
struct CertificationRequirement {
    environment: String,
    certification: Option<Envelope>,
    verify: VerifyContext,
}

pub struct ToolGate {
    pub mode: GateMode,
    /// The manifest digest (`sha256:<hex>`): the release identity.
    release: String,
    /// The release name (`release:` / legacy `metadata.agent`).
    release_name: String,
    /// `version:` / legacy `metadata.version`.
    version: String,
    /// The v1 manifest's policy file digest, if it references one.
    policy_digest: Option<String>,
    /// The manifest's policy file (as declared, and its bytes), if any.
    policy_source: Option<(String, Vec<u8>)>,
    /// The loaded policy; `None` with a `policy_source`: refuse every call.
    policy: Option<PolicyState>,
    tools: BTreeSet<String>,
    /// `None`: the release manifest alone decides (the default).
    #[cfg(feature = "certification")]
    certification: Option<CertificationRequirement>,
    /// `spec.policies` entries that bind tool contracts.
    contract_refs: BTreeSet<String>,
    /// Whether [`Self::with_contracts`] accepted the contracts the release binds.
    contracts_loaded: bool,
    /// Tool name -> its rules (from the v1 manifest or a bound contract).
    rules: BTreeMap<String, ToolRule>,
    /// The trusted task context (never from MCP messages).
    task: Option<Value>,
    /// Approval receipts; `None`: every approval-gated call is refused.
    approvals: Option<Approvals>,
    /// Where approval requests are filed, if anywhere.
    broker: Option<Arc<ApprovalBroker>>,
    /// The operations store for `sideEffect` tools.
    operations: Option<Arc<Mutex<OperationStore>>>,
    /// Operations the start-up sweep found left in flight (now `unknown`).
    recovered: Vec<String>,
    /// The operations store's key for derived operation ids.
    operation_id_key: Option<[u8; 32]>,
}

impl ToolGate {
    /// A gate for the release `manifest`: it allows the tools the manifest
    /// declares. Give it the tool contracts the release binds with
    /// [`Self::with_contracts`].
    pub fn new(mode: GateMode, manifest: &AgentRelease) -> Self {
        let tools = manifest
            .spec
            .tools
            .iter()
            .filter_map(|t| Reference::parse(&t.reference).ok())
            .map(|r| r.name)
            .collect();
        let contract_refs: BTreeSet<String> = manifest
            .spec
            .policies
            .iter()
            .map(|p| p.reference.clone())
            .filter(|r| contract::is_tool_contract_ref(r))
            .collect();
        Self {
            mode,
            release: manifest.manifest_hash().to_string(),
            release_name: manifest.metadata.agent.clone(),
            version: manifest.metadata.version.clone(),
            policy_digest: None,
            policy_source: None,
            policy: None,
            tools,
            #[cfg(feature = "certification")]
            certification: None,
            contracts_loaded: contract_refs.is_empty(),
            contract_refs,
            rules: BTreeMap::new(),
            task: None,
            approvals: None,
            broker: None,
            operations: None,
            recovered: Vec::new(),
            operation_id_key: None,
        }
    }

    /// A gate for a single-file v1 manifest: it allows the tools the
    /// manifest declares, with the rules it declares for them. Give it the
    /// trusted task context with [`Self::with_task_context`].
    pub fn from_manifest(mode: GateMode, manifest: &Manifest) -> Self {
        Self {
            mode,
            release: manifest.digest().to_string(),
            release_name: manifest.release.clone(),
            version: manifest.version.clone(),
            policy_digest: manifest.policy_digest().map(|d| d.to_string()),
            policy_source: manifest.policy.as_ref().map(|p| (p.path.display().to_string(), p.source.clone())),
            policy: None,
            tools: manifest.tools().keys().cloned().collect(),
            #[cfg(feature = "certification")]
            certification: None,
            contract_refs: BTreeSet::new(),
            contracts_loaded: true,
            rules: manifest.tools().clone(),
            task: None,
            approvals: None,
            broker: None,
            operations: None,
            recovered: Vec::new(),
            operation_id_key: None,
        }
    }

    /// Give the gate the trusted task context (never from MCP messages):
    /// `one_of_context` values, `{task.*}` key placeholders and `taskId`.
    pub fn with_task_context(mut self, task: Option<Value>) -> Result<Self, GateConfigError> {
        if task.as_ref().is_some_and(|t| !t.is_object()) {
            return Err(GateConfigError::TaskContextNotObject);
        }
        self.task = task;
        Ok(self)
    }

    /// Load the manifest's Cedar policy, with `counters` for its
    /// `context.counters` (and where forwarded calls are counted). An
    /// invalid policy is an error: the gate must not start. Without a
    /// `policy:` in the manifest this changes nothing.
    pub fn with_policy(mut self, counters: Counters) -> Result<Self, GateConfigError> {
        let Some((path, source)) = &self.policy_source else { return Ok(self) };
        let src = std::str::from_utf8(source).map_err(|_| GateConfigError::Policy(format!("policy {path}: not UTF-8")))?;
        let engine = PolicyEngine::parse(src).map_err(|e| GateConfigError::Policy(format!("policy {path}: {e}")))?;
        self.policy = Some(PolicyState { engine, counters: Mutex::new(counters) });
        Ok(self)
    }

    /// Whether the manifest references a Cedar policy.
    pub fn has_policy(&self) -> bool {
        self.policy_source.is_some()
    }

    /// The loaded policy's ids (`@id`, else `policyN`), sorted.
    pub fn policy_ids(&self) -> Vec<String> {
        self.policy.as_ref().map(|p| p.engine.policy_ids()).unwrap_or_default()
    }

    /// Count a call to `tool` the interceptor is about to forward at `now`
    /// (RFC 3339), for the policy's `context.counters`. `Ok(None)` without a
    /// policy. A counter store failure is `fail_closed`: an uncounted call
    /// could slip past a rate limit. Returns the id to
    /// [`Self::forget_forwarded`] if the call is not forwarded after all.
    pub fn record_forwarded(&self, tool: &str, now: &str) -> Result<Option<i64>, Denial> {
        let Some(policy) = &self.policy else {
            return if self.policy_source.is_some() { Err(Denial::FailClosed) } else { Ok(None) };
        };
        let now = unix(now)?;
        let counters = policy.counters.lock().map_err(|_| Denial::FailClosed)?;
        counters.record(&self.release_name, tool, now).map(Some).map_err(|e| {
            tracing::error!(error = %e, "call counter store failed");
            Denial::FailClosed
        })
    }

    /// Withdraw a call [`Self::record_forwarded`] counted that was not
    /// forwarded (answered from the operations store, or refused by it).
    pub fn forget_forwarded(&self, id: i64) {
        let Some(policy) = &self.policy else { return };
        if let Err(e) = policy.counters.lock().map_err(|_| "poisoned".to_string()).and_then(|c| c.forget(id).map_err(|e| e.0)) {
            // Over-counting is the safe direction: log and go on.
            tracing::warn!(error = %e, "could not withdraw a counted call");
        }
    }

    /// Evaluate the Cedar policy for a call that passed its contract.
    fn evaluate_policy(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<PolicyVerdict, Denial> {
        let Some(policy) = &self.policy else {
            return if self.policy_source.is_some() { Err(Denial::FailClosed) } else { Ok(PolicyVerdict::Allow) };
        };
        let now_unix = unix(now)?;
        let release: ReleaseHash = self.release.parse().map_err(|_| Denial::FailClosed)?;
        let fp = fingerprint(&release, tool, arguments.unwrap_or(&Value::Null)).to_string();
        let counters = {
            let store = policy.counters.lock().map_err(|_| Denial::FailClosed)?;
            store.snapshot(&self.release_name, self.tools.iter().map(String::as_str), now_unix).map_err(|e| {
                tracing::error!(error = %e, "call counter store failed");
                Denial::FailClosed
            })?
        };
        let input = CallInput {
            release: &self.release_name,
            tool,
            fingerprint: &fp,
            args: arguments,
            task: self.task.as_ref(),
            counters: &counters,
            now_unix,
        };
        match policy.engine.evaluate(&input) {
            Ok(PolicyDecision::Allow { .. }) => Ok(PolicyVerdict::Allow),
            Ok(PolicyDecision::RequireApproval { approvers, .. }) => Ok(PolicyVerdict::RequireApproval(approvers)),
            Ok(PolicyDecision::Deny { policies }) => Err(Denial::PolicyDenied { policies }),
            Err(e @ (PolicyError::Evaluation { .. } | PolicyError::Input(_) | PolicyError::Parse(_))) => {
                // Policy ids and value-free reasons only.
                tracing::warn!(tool, reason = %e, "Cedar could not decide: fail closed");
                Err(Denial::FailClosed)
            }
        }
    }

    /// Whether a call that passed its contract needs approval, and the routes:
    /// the manifest's rule or Cedar's `@approval` (either one requires it).
    fn approval_needed(&self, rule: &ToolRule, arguments: Option<&Value>, verdict: &PolicyVerdict) -> Option<Vec<String>> {
        let manifest = rule.needs_approval(arguments);
        let mut routes: Vec<String> =
            if manifest { rule.approval.as_ref().map(|a| a.approvers.clone()).unwrap_or_default() } else { Vec::new() };
        match verdict {
            PolicyVerdict::RequireApproval(cedar) => {
                for r in cedar {
                    if !routes.contains(r) {
                        routes.push(r.clone());
                    }
                }
                Some(routes)
            }
            PolicyVerdict::Allow if manifest => Some(routes),
            PolicyVerdict::Allow => None,
        }
    }

    /// Legacy (`certification` feature): also refuse every call unless
    /// `certification` verifies now for this release and `environment`.
    /// `verify` carries the trusted keys and revocations; its `now` and
    /// `expected_release` are set per check. `None`: every call is refused
    /// as `uncertified`.
    #[cfg(feature = "certification")]
    pub fn with_certification(mut self, environment: &str, certification: Option<Envelope>, verify: VerifyContext) -> Self {
        self.certification = Some(CertificationRequirement { environment: environment.to_string(), certification, verify });
        self
    }

    /// Give the gate the release's tool contracts and the trusted task
    /// context. Every supplied contract must be bound by the release
    /// (`spec.policies`), and every contract the release binds must be
    /// supplied; otherwise the gate must not start.
    pub fn with_contracts(mut self, contracts: Vec<ToolContract>, task: Option<Value>) -> Result<Self, GateConfigError> {
        if task.as_ref().is_some_and(|t| !t.is_object()) {
            return Err(GateConfigError::TaskContextNotObject);
        }
        let mut supplied = BTreeSet::new();
        let mut by_tool = BTreeMap::new();
        for c in contracts {
            let policy_ref = c.policy_ref();
            if !self.contract_refs.contains(&policy_ref) {
                return Err(GateConfigError::NotInRelease { policy_ref });
            }
            for (tool, rule) in &c.spec.tools {
                if by_tool.insert(tool.clone(), rule.clone()).is_some() {
                    return Err(GateConfigError::AmbiguousTool { tool: tool.clone() });
                }
            }
            supplied.insert(policy_ref);
        }
        if let Some(missing) = self.contract_refs.difference(&supplied).next() {
            return Err(GateConfigError::NotSupplied { policy_ref: missing.clone() });
        }
        self.rules = by_tool;
        self.task = task;
        self.contracts_loaded = true;
        Ok(self)
    }

    /// Read approval receipts from `dir` (`<fingerprint hex>.approval.json`)
    /// and accept those signed by one of `approvers`. Without this, every
    /// call to a tool whose contract requires approval is refused.
    pub fn with_approvals(mut self, dir: impl Into<PathBuf>, approvers: Vec<TrustedKey>) -> Self {
        self.approvals = Some(Approvals { dir: dir.into(), approvers });
        self
    }

    /// File approval requests with `broker` (built for this gate:
    /// [`ApprovalBroker::start`]) and honour its denials.
    pub fn with_broker(mut self, broker: Arc<ApprovalBroker>) -> Self {
        self.broker = Some(broker);
        self
    }

    /// Whether an approval broker is configured.
    pub fn has_broker(&self) -> bool {
        self.broker.is_some()
    }

    /// The approvals directory and the trusted approver keys, if set.
    pub fn approvals_config(&self) -> Option<(&std::path::Path, &[TrustedKey])> {
        self.approvals.as_ref().map(|a| (a.dir.as_path(), a.approvers.as_slice()))
    }

    /// Each declared tool with rules, and its `approval.ttl` in seconds
    /// (`None`: no bound).
    pub fn approval_ttls(&self) -> BTreeMap<String, Option<u64>> {
        self.rules
            .iter()
            .filter(|(tool, _)| self.tools.contains(*tool))
            .map(|(tool, rule)| (tool.clone(), rule.approval.as_ref().and_then(|a| a.ttl_secs)))
            .collect()
    }

    /// File an approval request for a call refused as `approval_required`
    /// with the broker, if there is one (it returns at once: the request is
    /// sent in the background). The request carries only the tool's
    /// `approval.show` values. `None` without a broker or when the call
    /// needs no approval.
    pub fn request_approval(&self, tool: &str, arguments: Option<&Value>, ledger_seq: Option<u64>) -> Option<RequestStatus> {
        let broker = self.broker.as_ref()?;
        let req = self.approval_request(tool, arguments)?;
        let rule = self.rules.get(tool)?;
        let release: ReleaseHash = self.release.parse().ok()?;
        let approval = rule.approval.as_ref();
        Some(broker.submit(BrokerRequest {
            fingerprint: fingerprint(&release, tool, arguments.unwrap_or(&Value::Null)),
            tool: tool.to_string(),
            approvers: req.approvers,
            ttl_secs: approval.and_then(|a| a.ttl_secs),
            shown: approval.map(|a| a.shown(arguments)).unwrap_or_default(),
            ledger_seq,
        }))
    }

    /// Track `sideEffect` operations in `store`. The gate takes the database
    /// for as long as it lives (an error if another gate holds it), and
    /// every operation a previous process left `in_flight` becomes `unknown`
    /// now (see [`Self::recovered_operations`]): one gate per operations
    /// database.
    pub fn with_operations(mut self, mut store: OperationStore) -> Result<Self, GateConfigError> {
        self.recovered = store.recover().map_err(|e| GateConfigError::OperationsStore(e.0))?;
        self.operation_id_key = Some(store.operation_id_key().map_err(|e| GateConfigError::OperationsStore(e.0))?);
        self.operations = Some(Arc::new(Mutex::new(store)));
        Ok(self)
    }

    /// Whether an operations store is configured.
    pub fn has_operations(&self) -> bool {
        self.operations.is_some()
    }

    /// The operations store, shared with the interceptor's reply thread.
    pub fn operations(&self) -> Option<Arc<Mutex<OperationStore>>> {
        self.operations.clone()
    }

    /// Operations the start-up sweep marked `unknown`.
    pub fn recovered_operations(&self) -> &[String] {
        &self.recovered
    }

    /// Can the gate run? A contract tool with `sideEffect: true` needs an
    /// operations store, and a manifest policy must be loaded.
    pub fn ready(&self) -> Result<(), GateConfigError> {
        if self.operations.is_none() {
            if let Some((tool, _)) = self.rules.iter().find(|(_, r)| r.side_effect) {
                return Err(GateConfigError::OperationsRequired { tool: tool.clone() });
            }
        }
        if self.policy_source.is_some() && self.policy.is_none() {
            return Err(GateConfigError::PolicyNotLoaded);
        }
        Ok(())
    }

    /// Whether the release declares `tool`.
    pub fn declares(&self, tool: &str) -> bool {
        self.tools.contains(tool)
    }

    /// The tools the release declares, sorted.
    pub fn declared_tools(&self) -> Vec<String> {
        self.tools.iter().cloned().collect()
    }

    /// The release's manifest hash (`sha256:<hex>`).
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The manifest digest (`sha256:<hex>`); the same as [`Self::release`].
    pub fn manifest_digest(&self) -> &str {
        &self.release
    }

    /// The v1 manifest's policy file digest (`sha256:<hex>`), if any.
    pub fn policy_digest(&self) -> Option<String> {
        self.policy_digest.clone()
    }

    /// The release name.
    pub fn release_name(&self) -> &str {
        &self.release_name
    }

    /// The release version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// For a call that needs approval: the routes and the fingerprint an
    /// approval broker needs. `None` when the call needs no approval (an
    /// undeclared tool, no approval rule, or a `when` that does not hold).
    ///
    /// The routes are the manifest's `approvers`, then the `@approval`
    /// values of the Cedar permits that hold now.
    pub fn approval_request(&self, tool: &str, arguments: Option<&Value>) -> Option<ApprovalRequest> {
        let rule = self.rules.get(tool).filter(|_| self.tools.contains(tool))?;
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let verdict = self.evaluate_policy(tool, arguments, &now).ok()?;
        let approvers = self.approval_needed(rule, arguments, &verdict)?;
        let release: ReleaseHash = self.release.parse().ok()?;
        let fp = fingerprint(&release, tool, arguments.unwrap_or(&Value::Null));
        Some(ApprovalRequest { approvers, fingerprint: fp.to_string() })
    }

    /// The release's manifest hash as bytes, for ledger binding.
    pub fn release_bytes(&self) -> [u8; 32] {
        self.release.parse::<cloakpipe_release::ReleaseHash>().map(|h| h.0).unwrap_or_default()
    }

    /// Check one call to `tool` with its raw (pre-masking) `arguments` at
    /// RFC 3339 time `now`.
    pub fn check(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<(), Denial> {
        self.authorize(tool, arguments, now).map(|_| ())
    }

    /// [`Self::check`], also returning what the call was allowed on (its
    /// approval receipt, when the contract requires one).
    pub fn authorize(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<Authorization, Denial> {
        if !self.tools.contains(tool) {
            return Err(Denial::UndeclaredTool);
        }
        #[cfg(feature = "certification")]
        if let Some(required) = &self.certification {
            self.check_certification(required, now)?;
        }
        if !self.contracts_loaded {
            return Err(Denial::ContractMissing);
        }
        let Some(rule) = self.rules.get(tool) else { return Ok(Authorization::default()) };
        // Contract, then Cedar, then approval: the first refusal wins.
        rule.check(arguments, self.task.as_ref())?;
        let verdict = self.evaluate_policy(tool, arguments, now)?;
        let needs_approval = self.approval_needed(rule, arguments, &verdict).is_some();
        let raw = arguments;
        let arguments = arguments.unwrap_or(&Value::Null);
        let approval = if needs_approval { Some(self.approve(rule, tool, arguments, now)?) } else { None };
        let operation = if rule.side_effect { Some(self.operation_key(rule, tool, raw, approval.as_ref())?) } else { None };
        Ok(Authorization { approval, operation })
    }

    /// Legacy (`certification` feature): does the certification certify the
    /// release now, for the gate's environment?
    #[cfg(feature = "certification")]
    fn check_certification(&self, required: &CertificationRequirement, now: &str) -> Result<(), Denial> {
        let Some(envelope) = &required.certification else { return Err(Denial::Uncertified) };
        let ctx = VerifyContext {
            now: now.to_string(),
            expected_release: Some(self.release.clone()),
            ..required.verify.clone()
        };
        let report = verify(envelope, &ctx);
        if !report.certified {
            let status = match report.status {
                // Verified, but the decision it attests is a block.
                Status::Valid | Status::ValidWithLimitations => "blocked".to_string(),
                other => serde_json::to_value(other)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_ascii_lowercase))
                    .unwrap_or_else(|| "invalid".into()),
            };
            return Err(Denial::NotCertified(status));
        }
        // Signed and verified: its scope can be trusted.
        match certified_environment(envelope) {
            Some(env) if env == required.environment => Ok(()),
            Some(env) => Err(Denial::WrongEnvironment(env)),
            None => Err(Denial::NotCertified("invalid".into())),
        }
    }

    /// The operation a call to `tool` is, whether or not it passes the gate:
    /// shadow mode forwards a call that fails it, and tracking a
    /// side-effecting call is not a release rule. `None` when the contract
    /// does not mark the tool `sideEffect: true`. The id is the approval
    /// receipt's `operationId` when a receipt for this call verifies, else the
    /// derived id.
    pub fn operation(&self, tool: &str, arguments: Option<&Value>, now: &str) -> Result<Option<OperationKey>, Denial> {
        let Some(rule) = self.rules.get(tool) else { return Ok(None) };
        if !rule.side_effect {
            return Ok(None);
        }
        let raw = arguments;
        let arguments = arguments.unwrap_or(&Value::Null);
        // Cedar's @approval counts too; a call it cannot decide has no receipt.
        let verdict = self.evaluate_policy(tool, raw, now).unwrap_or(PolicyVerdict::Allow);
        let needs_approval = self.approval_needed(rule, raw, &verdict).is_some();
        let approval = if needs_approval { self.approve(rule, tool, arguments, now).ok() } else { None };
        self.operation_key(rule, tool, raw, approval.as_ref()).map(Some)
    }

    /// The operation of a side-effecting call: the receipt's `operationId`,
    /// else from the tool's `idempotency_key` template, else derived from
    /// the task and the call.
    fn operation_key(
        &self,
        rule: &ToolRule,
        tool: &str,
        raw: Option<&Value>,
        approval: Option<&ApprovedCall>,
    ) -> Result<OperationKey, Denial> {
        if let Some(a) = approval {
            return Ok(OperationKey { operation_id: a.operation_id.clone(), fingerprint: a.fingerprint });
        }
        let release: ReleaseHash = self.release.parse().map_err(|_| Denial::OperationsUnavailable)?;
        let fp = fingerprint(&release, tool, raw.unwrap_or(&Value::Null));
        if let Some(template) = &rule.idempotency_key {
            let rendered = template.render(raw, self.task.as_ref())?;
            let key = self.operation_id_key.as_ref().ok_or(Denial::OperationsUnavailable)?;
            let operation_id = derive_idempotent_operation_id(key, &self.release_name, tool, &rendered);
            return Ok(OperationKey { operation_id, fingerprint: fp });
        }
        let task_id = self.task_id().ok_or(Denial::TaskContextMissing { path: None })?;
        // Without an operations store there is no key (and `ready` refuses).
        let key = self.operation_id_key.as_ref().ok_or(Denial::OperationsUnavailable)?;
        Ok(OperationKey { operation_id: derive_operation_id(key, task_id, &fp), fingerprint: fp })
    }

    /// The trusted task context's `taskId`.
    pub fn task_id(&self) -> Option<&str> {
        self.task.as_ref().and_then(|t| t.get("taskId")).and_then(Value::as_str)
    }

    /// Find and verify the approval receipt for this exact call, within the
    /// tool's approval ttl.
    fn approve(&self, rule: &ToolRule, tool: &str, arguments: &Value, now: &str) -> Result<ApprovedCall, Denial> {
        let Some(approvals) = &self.approvals else { return Err(Denial::ApprovalRequired) };
        let release: ReleaseHash = self.release.parse().map_err(|_| Denial::ApprovalInvalid)?;
        let fp = fingerprint(&release, tool, arguments);
        // A denial holds over any receipt.
        if let Some(now_unix) = parse_rfc3339(now).map(|t| t.timestamp()) {
            let hex = fp.hex();
            if self.broker.as_ref().is_some_and(|b| b.is_denied(&hex, now_unix)) || denial_in_force(&approvals.dir, &hex, now_unix) {
                return Err(Denial::ApprovalDenied);
            }
        }
        // The file name is hex: nothing from the call reaches the path.
        let path = approvals.dir.join(format!("{}.approval.json", fp.hex()));
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Denial::ApprovalRequired),
            Err(e) => {
                tracing::warn!(error = %e, "approval receipt unreadable");
                return Err(Denial::ApprovalInvalid);
            }
        };
        let Some(task_id) = self.task_id() else {
            return Err(Denial::TaskContextMissing { path: None });
        };
        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(|_| Denial::ApprovalInvalid)?;
        let check = ApprovalCheck {
            fingerprint: fp,
            release: &self.release,
            tool,
            task_id,
            approvers: &approvals.approvers,
            now,
        };
        match verify_approval(&envelope, &check) {
            Ok(a) if !within_ttl(rule, &a.approved_at, &a.not_after) => {
                tracing::warn!("approval receipt rejected: its validity window exceeds the tool's approval ttl");
                Err(Denial::ApprovalInvalid)
            }
            Ok(a) => Ok(ApprovedCall {
                receipt_digest: Sha256::digest(&bytes).into(),
                operation_id: a.operation_id,
                fingerprint: fp,
            }),
            Err(ApprovalError::Expired) => Err(Denial::ApprovalExpired),
            Err(e @ ApprovalError::Invalid(_)) => {
                // Receipt diagnostics only: never argument values.
                tracing::warn!(reason = %e, "approval receipt rejected");
                Err(Denial::ApprovalInvalid)
            }
        }
    }
}

/// Seconds since the epoch of an RFC 3339 time; unreadable: `fail_closed`.
fn unix(now: &str) -> Result<i64, Denial> {
    parse_rfc3339(now).map(|t| t.timestamp()).ok_or(Denial::FailClosed)
}

/// Whether a receipt's validity window (`notAfter - approvedAt`) fits the
/// tool's approval ttl (always, without one). Unparseable times do not fit.
fn within_ttl(rule: &ToolRule, approved_at: &str, not_after: &str) -> bool {
    let Some(ttl) = rule.approval.as_ref().and_then(|a| a.ttl_secs) else { return true };
    match (parse_rfc3339(approved_at), parse_rfc3339(not_after)) {
        (Some(from), Some(to)) => (to - from).num_seconds() <= i64::try_from(ttl).unwrap_or(i64::MAX),
        _ => false,
    }
}

/// `predicate.certification.environment` of a (verified) envelope.
#[cfg(feature = "certification")]
fn certified_environment(envelope: &Envelope) -> Option<String> {
    use base64::prelude::*;
    let payload = BASE64_STANDARD.decode(&envelope.payload).ok()?;
    let statement: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    statement.pointer("/predicate/certification/environment")?.as_str().map(str::to_string)
}
