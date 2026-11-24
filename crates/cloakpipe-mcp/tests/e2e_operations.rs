//! Operation identity and outcome states in the interceptor: a contract tool
//! with `sideEffect: true` runs through the operations store, so a call whose
//! outcome is unknown is never silently re-executed (docs/ACTION_BOUNDARY.md).

use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_core::{config::DetectionConfig, detector::Detector, vault::Vault, EntityCategory};
use cloakpipe_ledger::decision::{Decision, DecisionEntry, Event, Outcome};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::operations::{OperationState, OperationStore};
use cloakpipe_mcp::{reconcile_operation, run_proxy_io, DecisionLog, GateMode, PiiTransform, ProxyContext, ToolGate};
use cloakpipe_release::action::{derive_operation_id, fingerprint};
use cloakpipe_release::contract::ToolContract;
use cloakpipe_release::{parse_path, AgentRelease, ArtifactRef, Format};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::io::{Cursor, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn messages(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }
}

/// How the fake tool behaves. Every call it receives is "committed" by
/// appending one line to `effects.jsonl` before it answers (or not).
#[derive(Clone, Copy)]
enum Tool {
    /// Answers each call with a result echoing the tenant (masked under the
    /// PII transform).
    Ok,
    /// Commits the first call, then exits without replying (lost ack).
    LoseAck,
    /// Answers the first call with `isError: true`, later ones with a result.
    FailOnce,
}

fn fake_tool(dir: &Path, tool: Tool) -> Vec<String> {
    let effects = dir.join("effects.jsonl");
    let script = dir.join(format!("tool-{}.sh", uuid::Uuid::new_v4()));
    let reply = match tool {
        Tool::Ok => r#"printf '{"id":%s,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"patched %s"}]}}\n' "$id" "$tenant""#.to_string(),
        Tool::LoseAck => "exit 0".to_string(),
        Tool::FailOnce => format!(
            r#"if [ "$(wc -l < '{effects}')" -le 1 ]; then
    printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"conflict"}}],"isError":true}}}}\n' "$id"
  else
    printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"patched"}}]}}}}\n' "$id"
  fi"#,
            effects = effects.display()
        ),
    };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{effects}'
  id=$(printf '%s' "$line" | grep -o '"id":[0-9]*' | head -n 1 | cut -d: -f2)
  tenant=$(printf '%s' "$line" | sed 's/.*"tenant":"\([^"]*\)".*/\1/')
  {reply}
done
"#,
            effects = effects.display()
        ),
    )
    .unwrap();
    vec!["sh".into(), script.to_string_lossy().into_owned()]
}

/// A slow tool: each `tools/call` is committed (one line in `effects.jsonl`)
/// and answered with a result two seconds later; any other method gets an
/// immediate JSON-RPC error (a `slow/...` method gets it two seconds later). With `ask_roots`, the tool also sends the agent
/// its own `roots/list` request, under the same id as the call, right away.
fn slow_tool(dir: &Path, ask_roots: bool) -> Vec<String> {
    let effects = dir.join("effects.jsonl");
    let script = dir.join(format!("slow-{}.sh", uuid::Uuid::new_v4()));
    let ask = if ask_roots { r#"printf '{"jsonrpc":"2.0","id":%s,"method":"roots/list"}\n' "$id""# } else { ":" };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | grep -o '"id":[0-9]*' | head -n 1 | cut -d: -f2)
  case "$line" in
    *'"method":"tools/call"'*)
      printf '%s\n' "$line" >> '{effects}'
      {ask}
      (sleep 2; printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[{{"type":"text","text":"patched"}}]}}}}\n' "$id") &
      ;;
    *'"method":"slow/'*)
      (sleep 2; printf '{{"id":%s,"jsonrpc":"2.0","error":{{"code":-32601,"message":"method not found"}}}}\n' "$id") &
      ;;
    *'"method":'*)
      printf '{{"id":%s,"jsonrpc":"2.0","error":{{"code":-32601,"message":"method not found"}}}}\n' "$id"
      ;;
  esac
done
wait
"#,
            effects = effects.display()
        ),
    )
    .unwrap();
    vec!["sh".into(), script.to_string_lossy().into_owned()]
}

/// Run the interceptor over `upstream`, sending each line and then waiting
/// until the agent has received at least the given number of messages.
fn run_steps(dir: &Path, upstream: Vec<String>, gate: ToolGate, steps: &[(String, usize)]) -> Vec<Value> {
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let context = ctx(gate, &dir.join("ledger.db"));
    let writer = out.clone();
    let reader = proxy_side.try_clone().unwrap();
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    for (line, n) in steps {
        agent.write_all(format!("{line}\n").as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while out.messages().len() < *n {
            assert!(Instant::now() < deadline, "after {line}: {:?}", out.messages());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    handle.join().unwrap();
    out.messages()
}

fn effects(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("effects.jsonl")).map(|s| s.lines().count()).unwrap_or(0)
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
}

/// The example contract with operation tracking on and approval as given.
fn contract(approval: bool) -> ToolContract {
    let src = std::fs::read_to_string(example("crm-tools.contract.yaml"))
        .unwrap()
        .replace("requiresApproval: true", &format!("requiresApproval: {approval}"));
    ToolContract::parse_str(&src, Format::Yaml).unwrap()
}

fn release_binding(c: &ToolContract) -> AgentRelease {
    let mut m = parse_path(&example("release.yaml")).unwrap();
    m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
    m.spec.policies.push(ArtifactRef { reference: c.policy_ref() });
    m
}

fn task() -> Value {
    serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap()
}

/// A gate over the release manifest alone (no certification).
fn manifest_gate(m: &AgentRelease) -> ToolGate {
    ToolGate::new(GateMode::Enforce, m)
}

/// A gate for the side-effect contract (no approval) over the operations
/// database in `dir`.
fn gate(dir: &Path, t: Value) -> ToolGate {
    let c = contract(false);
    manifest_gate(&release_binding(&c))
        .with_contracts(vec![c], Some(t))
        .unwrap()
        .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
        .unwrap()
}

fn call(id: u64, arguments: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "crm.patch", "arguments": arguments}}).to_string()
}

fn args() -> Value {
    json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified", "note": "called back"}})
}

/// The derived id of a call in the operations database in `dir` (keyed by
/// that database's own key).
fn op_id(dir: &Path, arguments: &Value) -> String {
    let m = release_binding(&contract(false));
    let key = OperationStore::open(dir.join("ops.db")).unwrap().operation_id_key().unwrap();
    derive_operation_id(&key, "t-981", &fingerprint(&m.manifest_hash(), "crm.patch", arguments))
}

fn ctx(gate: ToolGate, ledger_db: &Path) -> ProxyContext {
    ctx_with(gate, ledger_db, None)
}

/// The PII transform (`mcp-proxy --transform pii`) over `vault`, with the
/// default detection config (emails on).
fn pii(vault: Vault) -> Option<PiiTransform> {
    Some(PiiTransform { detector: Detector::from_config(&serde_json::from_str::<DetectionConfig>("{}").unwrap()).unwrap(), vault })
}

/// The gate signing key every run and reconciliation signs with.
fn gate_key() -> GateKey {
    GateKey::from_seed([3; 32])
}

fn decision_log(ledger_db: &Path) -> DecisionLog {
    DecisionLog::open(ledger_db.to_str().unwrap(), gate_key()).unwrap()
}

fn ctx_with(gate: ToolGate, ledger_db: &Path, pii: Option<PiiTransform>) -> ProxyContext {
    ProxyContext {
        pii,
        ledger_db: Some(ledger_db.to_string_lossy().into_owned()),
        release: Some(gate.release_bytes()),
        gate: Some(gate),
        decisions: Some(decision_log(ledger_db)),
        events: Vec::new(),
        capture: None,
    }
}

/// The decision entries, after checking they verify offline.
fn ledger(ledger_db: &Path) -> Vec<DecisionEntry> {
    let entries = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap().decisions().unwrap();
    let values: Vec<Value> = entries.iter().map(|e| serde_json::to_value(e).unwrap()).collect();
    cloakpipe_verify::decisions::verify_decisions(&values, &[gate_key().public_key()]).expect("the entries verify");
    entries
}

/// Run the interceptor over `lines` (all sent at once).
fn run(dir: &Path, tool: Tool, gate: ToolGate, lines: &[String]) -> Vec<Value> {
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(fake_tool(dir, tool), ctx(gate, &dir.join("ledger.db")), input, out.clone()).unwrap();
    out.messages()
}

/// Run the interceptor, sending each line only after the previous request
/// has been answered (so a retry follows its first attempt's reply).
fn run_in_turn(dir: &Path, tool: Tool, gate: ToolGate, lines: &[String]) -> Vec<Value> {
    run_in_turn_with(dir, tool, gate, lines, None)
}

/// [`run_in_turn`] with the PII transform as given.
fn run_in_turn_with(dir: &Path, tool: Tool, gate: ToolGate, lines: &[String], pii: Option<PiiTransform>) -> Vec<Value> {
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let upstream = fake_tool(dir, tool);
    let context = ctx_with(gate, &dir.join("ledger.db"), pii);
    let writer = out.clone();
    let reader = proxy_side.try_clone().unwrap();
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    for (i, line) in lines.iter().enumerate() {
        agent.write_all(format!("{line}\n").as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while out.messages().len() <= i {
            assert!(Instant::now() < deadline, "no answer to {line}: {:?}", out.messages());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    handle.join().unwrap();
    let mut rest = Vec::new();
    let _ = agent.read_to_end(&mut rest);
    out.messages()
}

fn answer(msgs: &[Value], id: u64) -> &Value {
    msgs.iter().find(|m| m["id"] == id).unwrap_or_else(|| panic!("no answer for {id}: {msgs:?}"))
}

fn state(dir: &Path, op: &str) -> OperationState {
    OperationStore::open(dir.join("ops.db")).unwrap().get(op).unwrap().expect("row").state
}

/// An entry's refusal reason (the call was not forwarded).
fn denial(r: &DecisionEntry) -> Option<&str> {
    (r.decision != Decision::Allow && !r.forwarded).then_some(r.reason.as_str())
}

/// An entry's outcome, as recorded.
fn outcome(r: &DecisionEntry) -> Option<&'static str> {
    r.outcome.map(|o| match o {
        Outcome::Committed => "committed",
        Outcome::Failed => "failed",
        Outcome::Unknown => "unknown",
    })
}

#[test]
fn a_lost_acknowledgment_is_unknown_until_reconciled_and_never_re_executed() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());

    // 1. The tool commits the effect, then dies without replying.
    let msgs = run(dir.path(), Tool::LoseAck, gate(dir.path(), task()), &[call(1, &args())]);
    assert_eq!(effects(dir.path()), 1);
    assert_eq!(state(dir.path(), &op), OperationState::Unknown);
    let a = answer(&msgs, 1);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "operation_unknown", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");

    // 2. A retry is refused until an operator reconciles the operation.
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(2, &args())]);
    let a = answer(&msgs, 2);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "reconcile_before_retry", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");
    assert_eq!(effects(dir.path()), 1, "the retry never reached the tool");

    // 3. The operator checks the CRM: the patch did land.
    let ledger_db = dir.path().join("ledger.db");
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    let release = gate(dir.path(), task()).release().to_string();
    reconcile_operation(&mut store, &op, OperationState::Done, false, Some(&mut decision_log(&ledger_db)), Some(&release)).unwrap();
    drop(store);
    assert_eq!(state(dir.path(), &op), OperationState::Done);

    // 4. The retry replays instead of running the effect again.
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(3, &args())]);
    let a = answer(&msgs, 3);
    assert!(a.get("error").is_none(), "{a}");
    assert_eq!(a["result"]["_meta"]["cloakpipe"]["replayed"], true, "{a}");
    assert_eq!(effects(dir.path()), 1, "no second effect");

    // The ledger tells the story with ids and states only.
    let records = ledger(&ledger_db);
    let ops: Vec<(Event, Option<&str>)> = records
        .iter()
        .filter(|r| r.operation_id.as_deref() == Some(op.as_str()))
        .map(|r| (r.event, outcome(r).or(denial(r))))
        .collect();
    assert_eq!(
        ops,
        [
            (Event::Call, None),
            (Event::Outcome, Some("unknown")),
            (Event::Call, Some("reconcile_before_retry")),
            (Event::Reconcile, Some("committed")),
            (Event::Replay, Some("committed")),
        ],
        "{records:?}"
    );
    assert!(records[0].forwarded && !records[2].forwarded && !records[4].forwarded, "{records:?}");
    assert!(records.iter().all(|r| r.release.as_deref() == Some(release.as_str())), "every entry is bound to the release");
    assert!(records.iter().all(|r| r.tool.as_deref() == Some("crm.patch")), "{records:?}");
    let fp = records[0].args_fingerprint.clone().expect("keyed fingerprint");
    assert!(records.iter().all(|r| r.args_fingerprint.as_ref() == Some(&fp)), "one call, one fingerprint: {records:?}");
    let dump = serde_json::to_string(&records).unwrap();
    for raw in ["demo-co", "lead-42", "qualified", "called back"] {
        assert!(!dump.contains(raw), "{raw} leaked: {dump}");
    }
}

#[test]
fn a_reconciled_not_applied_operation_runs_again() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    run(dir.path(), Tool::LoseAck, gate(dir.path(), task()), &[call(1, &args())]);
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    reconcile_operation(&mut store, &op, OperationState::NotApplied, false, None, None).unwrap();
    drop(store);
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(2, &args())]);
    assert!(answer(&msgs, 2).get("result").is_some(), "{msgs:?}");
    assert_eq!(effects(dir.path()), 2);
    assert_eq!(state(dir.path(), &op), OperationState::Done);
}

#[test]
fn a_done_operation_replays_its_stored_raw_result_by_default() {
    let dir = tempfile::tempdir().unwrap();
    // No PII transform: the tool gets the raw tenant and the store keeps
    // the raw result, which a retry replays verbatim (no vault involved).
    let mut t = task();
    t["tenant"] = json!("ops@demo-co.example");
    let mut a = args();
    a["tenant"] = json!("ops@demo-co.example");
    let msgs = run_in_turn(dir.path(), Tool::Ok, gate(dir.path(), t), &[call(1, &a), call(2, &a)]);
    assert_eq!(effects(dir.path()), 1, "the retry was not forwarded");
    let first = answer(&msgs, 1);
    let replay = answer(&msgs, 2);
    assert_eq!(first["result"]["content"][0]["text"], "patched ops@demo-co.example", "{first}");
    assert_eq!(replay["result"]["content"], first["result"]["content"], "{replay}");
    assert_eq!(replay["result"]["_meta"]["cloakpipe"]["replayed"], true, "{replay}");

    let op = op_id(dir.path(), &a);
    let row = OperationStore::open(dir.path().join("ops.db")).unwrap().get(&op).unwrap().unwrap();
    assert_eq!(row.state, OperationState::Done);
    assert!(!row.result_masked, "a result stored without the PII transform is raw");
    assert!(row.result.unwrap().contains("ops@demo-co.example"));
}

#[test]
fn a_done_operation_replays_its_stored_result_rehydrated() {
    let dir = tempfile::tempdir().unwrap();
    // The tenant is an email: masked before the tool, echoed back masked.
    let mut t = task();
    t["tenant"] = json!("ops@demo-co.example");
    let mut a = args();
    a["tenant"] = json!("ops@demo-co.example");
    let msgs = run_in_turn_with(dir.path(), Tool::Ok, gate(dir.path(), t), &[call(1, &a), call(2, &a)], pii(Vault::ephemeral()));
    assert_eq!(effects(dir.path()), 1, "the retry was not forwarded");
    let first = answer(&msgs, 1);
    let replay = answer(&msgs, 2);
    assert_eq!(first["result"]["content"][0]["text"], "patched ops@demo-co.example", "{first}");
    assert_eq!(replay["result"]["content"], first["result"]["content"], "{replay}");
    assert_eq!(replay["result"]["_meta"]["cloakpipe"]["replayed"], true, "{replay}");
    assert!(first["result"].get("_meta").is_none(), "{first}");

    // The store holds the masked result only.
    let op = op_id(dir.path(), &a);
    let row = OperationStore::open(dir.path().join("ops.db")).unwrap().get(&op).unwrap().unwrap();
    assert_eq!(row.state, OperationState::Done);
    assert!(row.result_masked, "stored under the PII transform");
    let stored = row.result.unwrap();
    assert!(stored.contains("patched") && !stored.contains("ops@demo-co.example"), "{stored}");
}

/// An operations database as v0.11 wrote it (always-on masking, no
/// `result_masked` column), holding one `done` operation for `args()` whose
/// stored result carries the pseudonym `token`. Returns the operation id.
fn v011_database(dir: &Path, token: &str) -> String {
    let key = [7u8; 32];
    let m = release_binding(&contract(false));
    let op = derive_operation_id(&key, "t-981", &fingerprint(&m.manifest_hash(), "crm.patch", &args()));
    let digest = fingerprint(&m.manifest_hash(), "crm.patch", &args()).0;
    let conn = rusqlite::Connection::open(dir.join("ops.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE operations (
            operation_id TEXT PRIMARY KEY,
            tool TEXT,
            call_digest BLOB,
            state TEXT,
            result TEXT,
            updated_at TEXT
        );
        CREATE TABLE operation_id_key (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            key BLOB NOT NULL CHECK (length(key) = 32)
        );",
    )
    .unwrap();
    conn.execute("INSERT INTO operation_id_key (id, key) VALUES (1, ?1)", rusqlite::params![&key[..]]).unwrap();
    let result = json!({"content": [{"type": "text", "text": format!("patched, receipt sent to {token}")}]}).to_string();
    conn.execute(
        "INSERT INTO operations VALUES (?1, 'crm.patch', ?2, 'done', ?3, '2026-10-01T00:00:00.000Z')",
        rusqlite::params![op, &digest[..], result],
    )
    .unwrap();
    op
}

#[test]
fn replay_of_v011_masked_row_without_vault_refuses_or_rehydrates() {
    let dir = tempfile::tempdir().unwrap();
    // The vault the row was masked through knows EMAIL_1.
    let mut vault = Vault::ephemeral();
    let token = vault.get_or_create("ops@demo-co.example", &EntityCategory::Email).token;
    let op = v011_database(dir.path(), &token);

    // 1. No PII transform (the new default): replaying the row would hand
    //    the agent pseudonym tokens, so the proxy refuses to start.
    let out = Capture::default();
    let err = run_proxy_io(fake_tool(dir.path(), Tool::Ok), ctx(gate(dir.path(), task()), &dir.path().join("ledger.db")), Cursor::new(format!("{}\n", call(1, &args())).into_bytes()), out.clone())
        .expect_err("refused to start");
    let msg = err.to_string();
    assert!(msg.contains("--transform pii"), "{msg}");
    assert!(msg.contains("masked"), "{msg}");
    assert!(out.messages().is_empty(), "nothing was answered: {:?}", out.messages());
    assert_eq!(effects(dir.path()), 0, "the tool was never started or called");
    assert_eq!(state(dir.path(), &op), OperationState::Done, "the row is left as it was");

    // 2. With the PII transform and the vault: the retry replays the stored
    //    result rehydrated, and the effect is not run again.
    let msgs = run_in_turn_with(dir.path(), Tool::Ok, gate(dir.path(), task()), &[call(2, &args())], pii(vault));
    let a = answer(&msgs, 2);
    assert_eq!(a["result"]["content"][0]["text"], "patched, receipt sent to ops@demo-co.example", "{a}");
    assert_eq!(a["result"]["_meta"]["cloakpipe"]["replayed"], true, "{a}");
    assert_eq!(effects(dir.path()), 0, "no second effect");
}

#[test]
fn a_failed_operation_may_be_retried() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    let msgs = run_in_turn(dir.path(), Tool::FailOnce, gate(dir.path(), task()), &[call(1, &args()), call(2, &args())]);
    assert_eq!(answer(&msgs, 1)["result"]["isError"], true, "{msgs:?}");
    assert_eq!(answer(&msgs, 2)["result"]["content"][0]["text"], "patched", "{msgs:?}");
    assert_eq!(effects(dir.path()), 2, "the retry ran");
    assert_eq!(state(dir.path(), &op), OperationState::Done);
    let states: Vec<_> = ledger(&dir.path().join("ledger.db"))
        .iter()
        .filter(|r| r.event == Event::Outcome)
        .filter_map(|r| outcome(r).map(str::to_string))
        .collect();
    assert_eq!(states, ["failed", "committed"]);
}

/// Another agent request reusing the id of a side-effecting call in flight
/// is refused: its reply would otherwise settle the operation `failed` and
/// let a retry run the effect a second time.
#[test]
fn a_request_reusing_an_in_flight_operations_id_cannot_settle_it() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    let bogus = json!({"jsonrpc": "2.0", "id": 1, "method": "bogus/method"}).to_string();
    let msgs = run_steps(
        dir.path(),
        slow_tool(dir.path(), false),
        gate(dir.path(), task()),
        &[(call(1, &args()), 0), (bogus, 1), (call(2, &args()), 2)],
    );
    assert_eq!(effects(dir.path()), 1, "the effect ran once: {msgs:?}");
    assert_eq!(state(dir.path(), &op), OperationState::Done, "{msgs:?}");
    let refused = &msgs[0];
    assert_eq!(refused["id"], 1, "{msgs:?}");
    assert_eq!(refused["error"]["data"]["reason"], "request_id_in_use", "{msgs:?}");
    assert_eq!(answer(&msgs, 2)["error"]["data"]["reason"], "reconcile_before_retry", "{msgs:?}");
    let replies: Vec<_> = msgs.iter().filter(|m| m["id"] == 1 && m.get("result").is_some()).collect();
    assert_eq!(replies.len(), 1, "the call's own reply still reaches the agent: {msgs:?}");
}

/// `--gate warn` forwards a call that fails the gate, and still tracks it
/// as an operation: a lost reply is unknown and a retry is refused.
#[test]
fn shadow_mode_tracks_a_side_effecting_call_that_fails_the_gate() {
    let dir = tempfile::tempdir().unwrap();
    let warn_gate = |dir: &Path| {
        // Approval required and no receipt: approval_required, forwarded in shadow mode.
        let c = contract(true);
        let mut g = manifest_gate(&release_binding(&c))
            .with_contracts(vec![c], Some(task()))
            .unwrap()
            .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
            .unwrap();
        g.mode = GateMode::Shadow;
        g
    };
    let msgs = run(dir.path(), Tool::LoseAck, warn_gate(dir.path()), &[call(1, &args())]);
    assert_eq!(effects(dir.path()), 1, "shadow mode forwarded the call: {msgs:?}");
    let ops = OperationStore::open(dir.path().join("ops.db")).unwrap().list(None).unwrap();
    assert_eq!(ops.len(), 1, "the forwarded call is an operation: {msgs:?}");
    let op = ops[0].operation_id.clone();
    assert_eq!(ops[0].state, OperationState::Unknown);
    assert_eq!(answer(&msgs, 1)["error"]["data"]["reason"], "operation_unknown", "{msgs:?}");

    let msgs = run(dir.path(), Tool::Ok, warn_gate(dir.path()), &[call(2, &args())]);
    assert_eq!(answer(&msgs, 2)["error"]["data"]["reason"], "reconcile_before_retry", "{msgs:?}");
    assert_eq!(effects(dir.path()), 1, "the retry never reached the tool");

    let records = ledger(&dir.path().join("ledger.db"));
    let forwarded = records.iter().find(|r| r.event == Event::Call).unwrap();
    assert_eq!((forwarded.decision, forwarded.reason.as_str()), (Decision::RequireApproval, "approval_required"), "{records:?}");
    assert!(forwarded.forwarded, "{records:?}");
    assert_eq!(forwarded.operation_id.as_deref(), Some(op.as_str()), "{records:?}");
}

/// A reply to an operation that is no longer in flight (an operator
/// reconciled it meanwhile) changes nothing, and the ledger does not claim
/// it settled.
#[test]
fn a_reply_to_an_operation_reconciled_meanwhile_records_no_settlement() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    let ledger_db = dir.path().join("ledger.db");
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let context = ctx(gate(dir.path(), task()), &ledger_db);
    let (writer, reader, upstream) = (out.clone(), proxy_side.try_clone().unwrap(), slow_tool(dir.path(), false));
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    agent.write_all(format!("{}\n", call(1, &args())).as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while effects(dir.path()) == 0 {
        assert!(Instant::now() < deadline, "the call never reached the tool");
        std::thread::sleep(Duration::from_millis(10));
    }
    // The operator decides it did not happen while the reply is still due.
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    reconcile_operation(&mut store, &op, OperationState::NotApplied, true, Some(&mut decision_log(&ledger_db)), None).unwrap();
    drop(store);
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    handle.join().unwrap();
    assert!(answer(&out.messages(), 1).get("result").is_some(), "{:?}", out.messages());
    assert_eq!(state(dir.path(), &op), OperationState::NotApplied);
    let records = ledger(&ledger_db);
    let states: Vec<_> = records
        .iter()
        .filter(|r| r.operation_id.as_deref() == Some(op.as_str()))
        .filter_map(|r| outcome(r).map(|s| (r.event, s.to_string())))
        .collect();
    assert_eq!(states, [(Event::Reconcile, "failed".to_string())], "{records:?}");
}

/// A tool that commits each call, then waits for `go` in `dir` and exits
/// without replying (a lost acknowledgment the test controls the timing of).
fn held_tool(dir: &Path) -> Vec<String> {
    let script = dir.join(format!("held-{}.sh", uuid::Uuid::new_v4()));
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nwhile IFS= read -r line; do\n  printf '%s\\n' \"$line\" >> '{effects}'\n  while [ ! -e '{go}' ]; do sleep 0.05; done\n  exit 0\ndone\n",
            effects = dir.join("effects.jsonl").display(),
            go = dir.join("go").display()
        ),
    )
    .unwrap();
    vec!["sh".into(), script.to_string_lossy().into_owned()]
}

/// The upstream goes away after an operator already reconciled the call:
/// the exit sweep changes nothing and records no `unknown`, but the request
/// is still answered, with `operation_reconciled` and the reconciled state.
#[test]
fn the_exit_sweep_leaves_an_operation_reconciled_meanwhile_alone() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    let ledger_db = dir.path().join("ledger.db");
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let context = ctx(gate(dir.path(), task()), &ledger_db);
    let (writer, reader, upstream) = (out.clone(), proxy_side.try_clone().unwrap(), held_tool(dir.path()));
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    agent.write_all(format!("{}\n", call(1, &args())).as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while effects(dir.path()) == 0 {
        assert!(Instant::now() < deadline, "the call never reached the tool");
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut store = OperationStore::open(dir.path().join("ops.db")).unwrap();
    reconcile_operation(&mut store, &op, OperationState::Done, true, Some(&mut decision_log(&ledger_db)), None).unwrap();
    drop(store);
    std::fs::write(dir.path().join("go"), b"").unwrap();
    handle.join().unwrap();
    drop(proxy_side);
    assert_eq!(state(dir.path(), &op), OperationState::Done);
    let msgs = out.messages();
    assert!(msgs.iter().all(|m| m["error"]["data"]["reason"] != "operation_unknown"), "{msgs:?}");
    // The request is still answered: an MCP client must never wait forever.
    let a = answer(&msgs, 1);
    assert_eq!(a["error"]["code"], -32002, "{a}");
    assert_eq!(a["error"]["data"]["reason"], "operation_reconciled", "{a}");
    assert_eq!(a["error"]["data"]["operationId"], op.as_str(), "{a}");
    assert_eq!(a["error"]["data"]["state"], "done", "{a}");
    let records = ledger(&ledger_db);
    let states: Vec<_> = records
        .iter()
        .filter(|r| r.operation_id.as_deref() == Some(op.as_str()))
        .filter_map(|r| outcome(r).map(|s| (r.event, s.to_string())))
        .collect();
    assert_eq!(states, [(Event::Reconcile, "committed".to_string())], "{records:?}");
}

/// While a side-effecting call waits for the operations database (an
/// operator's `operations reconcile` holds its write lock), replies to other
/// requests still reach the agent.
#[test]
fn replies_are_not_held_up_while_a_call_waits_for_the_operations_database() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path(), task());
    let (held, released) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let locker = {
        let (db, held, released) = (dir.path().join("ops.db"), held.clone(), released.clone());
        std::thread::spawn(move || {
            let conn = rusqlite::Connection::open(db).unwrap();
            conn.execute_batch("BEGIN IMMEDIATE").unwrap();
            held.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_secs(6));
            released.store(true, Ordering::SeqCst);
            conn.execute_batch("COMMIT").unwrap();
        })
    };
    while !held.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let context = ctx(g, &dir.path().join("ledger.db"));
    let (writer, reader, upstream) = (out.clone(), proxy_side.try_clone().unwrap(), slow_tool(dir.path(), false));
    let handle = std::thread::spawn(move || run_proxy_io(upstream, context, reader, writer).unwrap());
    let slow = json!({"jsonrpc": "2.0", "id": 5, "method": "slow/method"}).to_string();
    agent.write_all(format!("{slow}\n{}\n", call(1, &args())).as_bytes()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut slow_answered_while_locked = None;
    loop {
        let msgs = out.messages();
        if slow_answered_while_locked.is_none() && msgs.iter().any(|m| m["id"] == 5) {
            slow_answered_while_locked = Some(!released.load(Ordering::SeqCst));
        }
        if msgs.iter().any(|m| m["id"] == 1) {
            break;
        }
        assert!(Instant::now() < deadline, "{msgs:?}");
        std::thread::sleep(Duration::from_millis(10));
    }
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    handle.join().unwrap();
    locker.join().unwrap();
    let msgs = out.messages();
    assert_eq!(slow_answered_while_locked, Some(true), "the unrelated reply waited for the database: {msgs:?}");
    assert!(answer(&msgs, 1).get("result").is_some(), "{msgs:?}");
    assert_eq!(effects(dir.path()), 1);
}

/// A side-effecting call may not reuse the id of another request still
/// waiting for its reply either.
#[test]
fn a_side_effecting_call_reusing_an_outstanding_request_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let slow = json!({"jsonrpc": "2.0", "id": 1, "method": "slow/method"}).to_string();
    let msgs = run_steps(dir.path(), slow_tool(dir.path(), false), gate(dir.path(), task()), &[(slow, 0), (call(1, &args()), 1)]);
    assert_eq!(msgs[0]["error"]["data"]["reason"], "request_id_in_use", "{msgs:?}");
    assert_eq!(effects(dir.path()), 0, "{msgs:?}");
}

/// A request from the upstream (sampling, roots/list, ping) whose id equals
/// an in-flight call's id is not that call's reply.
#[test]
fn an_upstream_request_with_an_in_flight_id_does_not_settle_the_operation() {
    let dir = tempfile::tempdir().unwrap();
    let op = op_id(dir.path(), &args());
    let msgs = run_steps(
        dir.path(),
        slow_tool(dir.path(), true),
        gate(dir.path(), task()),
        &[(call(1, &args()), 1), (call(2, &args()), 2)],
    );
    assert_eq!(msgs[0]["method"], "roots/list", "the upstream request reaches the agent: {msgs:?}");
    assert_eq!(answer(&msgs, 2)["error"]["data"]["reason"], "reconcile_before_retry", "{msgs:?}");
    assert_eq!(effects(dir.path()), 1, "the effect ran once: {msgs:?}");
    assert_eq!(state(dir.path(), &op), OperationState::Done);
    let states: Vec<_> = ledger(&dir.path().join("ledger.db"))
        .iter()
        .filter(|r| r.event == Event::Outcome)
        .filter_map(|r| outcome(r).map(str::to_string))
        .collect();
    assert_eq!(states, ["committed"]);
}

#[test]
fn a_side_effect_notification_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let note = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "crm.patch", "arguments": args()}}).to_string();
    let msgs = run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[note]);
    assert!(msgs.is_empty(), "a notification gets no answer: {msgs:?}");
    assert_eq!(effects(dir.path()), 0);
    let records = ledger(&dir.path().join("ledger.db"));
    assert!(records.iter().any(|r| denial(r) == Some("request_id_missing")), "{records:?}");
}

#[test]
fn start_up_marks_operations_left_in_flight_unknown_with_evidence() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut s = OperationStore::open(dir.path().join("ops.db")).unwrap();
        s.begin("op-crashed", "crm.patch", &[9; 32]).unwrap();
    }
    run(dir.path(), Tool::Ok, gate(dir.path(), task()), &[]);
    assert_eq!(state(dir.path(), "op-crashed"), OperationState::Unknown);
    let records = ledger(&dir.path().join("ledger.db"));
    let swept: Vec<_> = records.iter().filter(|r| r.operation_id.as_deref() == Some("op-crashed")).collect();
    assert_eq!(swept.len(), 1, "{records:?}");
    assert_eq!(swept[0].event, Event::Outcome);
    assert_eq!(outcome(swept[0]), Some("unknown"));
}

#[test]
fn a_side_effect_gate_without_an_operations_store_does_not_start() {
    let dir = tempfile::tempdir().unwrap();
    let c = contract(false);
    let g = manifest_gate(&release_binding(&c)).with_contracts(vec![c], Some(task())).unwrap();
    let err = run_proxy_io(fake_tool(dir.path(), Tool::Ok), ctx(g, &dir.path().join("ledger.db")), Cursor::new(Vec::new()), Capture::default())
        .expect_err("refused");
    assert!(err.to_string().contains("--operations-db"), "{err}");
}

mod approvals {
    use super::*;
    use cloakpipe_receipt::approval::{sign_approval, Approval};

    fn approver() -> SigningKey {
        SigningKey::from_bytes(&[21u8; 32])
    }

    fn approval_gate(dir: &Path) -> ToolGate {
        let c = contract(true);
        let trusted = vec![TrustedKey { keyid: "approver-1".into(), public_key: approver().verifying_key().to_bytes() }];
        manifest_gate(&release_binding(&c))
            .with_contracts(vec![c], Some(task()))
            .unwrap()
            .with_approvals(dir, trusted)
            .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
            .unwrap()
    }

    /// File a receipt approving `arguments` as operation `operation_id`.
    fn approve(dir: &Path, arguments: &Value, operation_id: &str) {
        let release = release_binding(&contract(true)).manifest_hash();
        let fp = fingerprint(&release, "crm.patch", arguments);
        let now = chrono::Utc::now();
        let ts = |t: chrono::DateTime<chrono::Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let a = Approval {
            release: release.to_string(),
            tool: "crm.patch".into(),
            task_id: "t-981".into(),
            operation_id: operation_id.into(),
            approver: "approver-1".into(),
            approved_at: ts(now - chrono::Duration::minutes(1)),
            not_after: ts(now + chrono::Duration::minutes(15)),
        };
        let bytes = serde_json::to_vec(&sign_approval(&fp, &a, &approver(), "approver-1")).unwrap();
        std::fs::write(dir.join(format!("{}.approval.json", fp.hex())), bytes).unwrap();
    }

    #[test]
    fn conflicting_arguments_under_one_operation_id_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut other = args();
        other["patch"]["stage"] = json!("review");
        approve(dir.path(), &args(), "op-crm-7");
        approve(dir.path(), &other, "op-crm-7");
        let msgs = run(dir.path(), Tool::Ok, approval_gate(dir.path()), &[call(1, &args()), call(2, &other)]);
        assert!(answer(&msgs, 1).get("result").is_some(), "{msgs:?}");
        let a = answer(&msgs, 2);
        assert_eq!(a["error"]["code"], -32001, "{a}");
        assert_eq!(a["error"]["data"]["reason"], "operation_conflict", "{a}");
        assert_eq!(a["error"]["data"]["operationId"], "op-crm-7", "{a}");
        assert_eq!(effects(dir.path()), 1, "the conflicting call never reached the tool");
        let records = ledger(&dir.path().join("ledger.db"));
        let denied: Vec<_> = records.iter().filter(|r| denial(r) == Some("operation_conflict")).collect();
        assert_eq!(denied.len(), 1, "{records:?}");
        assert_eq!(denied[0].operation_id.as_deref(), Some("op-crm-7"));
    }

    #[test]
    fn an_approved_operation_is_tracked_under_the_receipts_operation_id() {
        let dir = tempfile::tempdir().unwrap();
        approve(dir.path(), &args(), "op-crm-8");
        let msgs = run(dir.path(), Tool::Ok, approval_gate(dir.path()), &[call(1, &args())]);
        assert!(answer(&msgs, 1).get("result").is_some(), "{msgs:?}");
        assert_eq!(state(dir.path(), "op-crm-8"), OperationState::Done);
        let records = ledger(&dir.path().join("ledger.db"));
        let call = records.iter().find(|r| r.event == Event::Call).unwrap();
        assert!(call.approval.is_some());
        assert_eq!(call.operation_id.as_deref(), Some("op-crm-8"));
    }
}

/// docs/ACTION_BOUNDARY.md names the identifiers, codes and states the code uses.
#[test]
fn the_docs_name_what_the_code_uses() {
    use cloakpipe_mcp::proxy::RECONCILE_REQUIRED;
    use cloakpipe_mcp::Denial;
    let docs = std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/ACTION_BOUNDARY.md")).unwrap();
    let op = || "op-1".to_string();
    let denials = [
        Denial::OperationConflict { operation_id: op() },
        Denial::ReconcileBeforeRetry { operation_id: op() },
        Denial::OperationsUnavailable,
        Denial::RequestIdMissing,
        Denial::RequestIdInUse,
    ];
    let mut names: Vec<String> = denials.iter().map(|d| d.code()).collect();
    names.extend(
        [OperationState::InFlight, OperationState::Done, OperationState::Failed, OperationState::Unknown, OperationState::NotApplied]
            .iter()
            .map(|s| s.to_string()),
    );
    names.push(cloakpipe_release::action::OPERATION_ID_DOMAIN.to_string());
    names.push(RECONCILE_REQUIRED.to_string());
    for n in ["operation_unknown", "operation_id_key", "HMAC-SHA256", "--operations-db", "CLOAKPIPE_OPERATIONS_DB", "cloakpipe.decision/v1", "fail_closed"] {
        names.push(n.to_string());
    }
    for n in names {
        assert!(docs.contains(&format!("`{n}`")) || docs.contains(&n), "docs/ACTION_BOUNDARY.md does not mention {n}");
    }
}
