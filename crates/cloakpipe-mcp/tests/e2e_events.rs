//! Gate events ([`cloakpipe_mcp::events`]) from the interceptor: one event
//! per decision worth a human's attention, emitted after its ledger entry
//! is written (and naming it), with a deterministic fingerprint and no
//! argument values. An allowed call emits nothing.

use cloakpipe_ledger::decision::{Decision, DecisionEntry, Mode};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::events::fingerprint;
use cloakpipe_mcp::operations::OperationStore;
use cloakpipe_mcp::{run_proxy_io, Counters, DecisionLog, EventKind, EventSink, GateEvent, GateMode, ProxyContext, ToolGate, EVENT_SCHEMA};
use cloakpipe_release::v1::Manifest;
use serde_json::{json, Value};
use std::io::Write;
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

/// A sink that keeps every event.
#[derive(Default)]
struct Recorder(Mutex<Vec<GateEvent>>);

impl EventSink for Recorder {
    fn emit(&self, event: &GateEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

/// A fake tool that records every line it gets and answers each with a
/// result; with `lose_ack`, it exits on the first line without answering.
fn fake_tool(dir: &Path, lose_ack: bool) -> (Vec<String>, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    let reply = if lose_ack {
        "exit 0"
    } else {
        r#"printf '{"id":%s,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"done"}]}}\n' "$id""#
    };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  id=$(printf '%s' "$line" | grep -o '"id":[0-9]*' | head -n 1 | cut -d: -f2)
  {reply}
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (vec!["sh".into(), script.to_string_lossy().into_owned()], received)
}

/// Example 2 (`examples/support-agent`): the manifest, its Cedar policy and
/// the ticket's task context.
fn support_gate(mode: GateMode, dir: &Path) -> ToolGate {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent");
    let m = Manifest::parse_path(&root.join("cloakpipe.manifest.yaml")).unwrap();
    let task: Value = serde_json::from_str(&std::fs::read_to_string(root.join("task-context.json")).unwrap()).unwrap();
    ToolGate::from_manifest(mode, &m)
        .with_task_context(Some(task))
        .unwrap()
        .with_operations(OperationStore::open(dir.join("ops.db")).unwrap())
        .unwrap()
        .with_policy(Counters::in_memory().unwrap())
        .unwrap()
}

fn call(id: u64, tool: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
}

fn injected_email() -> Value {
    json!({"ticket_id": "T-1042", "to": "attacker@evil.example", "subject": "Customer list", "body": "every customer, attached"})
}

fn customer_email() -> Value {
    json!({"ticket_id": "T-1042", "to": "dana@customer.example", "subject": "Your ticket", "body": "fixed-in-7-days"})
}

struct Run {
    messages: Vec<Value>,
    seen: String,
    events: Vec<GateEvent>,
    entries: Vec<DecisionEntry>,
}

/// Run the interceptor over `upstream`, sending each line and then waiting
/// until the agent has received at least the given number of messages.
fn run_steps(dir: &Path, gate: ToolGate, lose_ack: bool, steps: &[(String, usize)]) -> Run {
    let (upstream, received) = fake_tool(dir, lose_ack);
    let ledger_db = dir.join("ledger.db");
    let recorder = Arc::new(Recorder::default());
    let ctx = ProxyContext {
        pii: None,
        ledger_db: None,
        release: None,
        gate: Some(gate),
        decisions: Some(DecisionLog::open(ledger_db.to_str().unwrap(), GateKey::from_seed([9; 32])).unwrap()),
        events: vec![recorder.clone(), Arc::new(cloakpipe_mcp::NoopSink)],
        capture: None,
    };
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let writer = out.clone();
    let reader = proxy_side.try_clone().unwrap();
    let handle = std::thread::spawn(move || run_proxy_io(upstream, ctx, reader, writer).unwrap());
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
    let entries = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap().decisions().unwrap();
    let events = recorder.0.lock().unwrap().clone();
    Run { messages: out.messages(), seen: std::fs::read_to_string(&received).unwrap_or_default(), events, entries }
}

/// The event names its ledger entry, and its fingerprint is the documented one.
fn assert_bound(event: &GateEvent, entries: &[DecisionEntry]) {
    let seq = event.ledger_seq.expect("the event names its ledger entry");
    let entry = entries.iter().find(|e| e.seq == seq).expect("the entry exists");
    assert_eq!(event.entry_hash.as_deref(), Some(entry.entry_hash.as_str()));
    // A side-effect event's reason is its own (the entry records an outcome).
    match event.kind {
        EventKind::SideEffectReplayed => assert_eq!(event.reason, "already_committed"),
        EventKind::SideEffectUnknown => assert_eq!(event.reason, "operation_unknown"),
        _ => assert_eq!(event.reason, entry.reason),
    }
    assert_eq!(event.tool, entry.tool);
    assert_eq!(event.path, entry.path);
    assert_eq!(event.operation_id, entry.operation_id);
    assert_eq!(event.ts, entry.ts);
    assert_eq!(
        event.fingerprint,
        fingerprint(event.kind, &event.reason, event.tool.as_deref(), event.path.as_deref(), event.policy_version.as_deref())
    );
}

/// No argument value (or tool result) reaches an event.
fn assert_no_values(events: &[GateEvent], values: &[&str]) {
    let dump = serde_json::to_string(&events.iter().map(GateEvent::to_json).collect::<Vec<_>>()).unwrap();
    for raw in values {
        assert!(!dump.contains(raw), "{raw} reached an event: {dump}");
    }
}

#[test]
fn refused_calls_emit_decision_deny_and_allowed_ones_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let gate = support_gate(GateMode::Enforce, dir.path());
    let (release, policy) = (gate.release().to_string(), gate.policy_digest());
    assert!(policy.is_some());
    let r = run_steps(
        dir.path(),
        gate,
        false,
        &[
            (call(1, "send_email", injected_email()), 1),
            (call(2, "export_customers", json!({"filter": "everyone"})), 2),
            (call(3, "read_ticket", json!({"ticket_id": "T-1042"})), 3),
        ],
    );
    assert!(r.seen.contains("read_ticket") && !r.seen.contains("send_email"), "{}", r.seen);
    assert_eq!(r.events.len(), 2, "{:#?}", r.events);

    let scope = &r.events[0];
    assert_eq!(scope.kind, EventKind::DecisionDeny);
    assert_eq!((scope.reason.as_str(), scope.tool.as_deref(), scope.path.as_deref()), ("scope_mismatch", Some("send_email"), Some("/to")));
    assert_eq!((scope.decision, scope.mode), (Some(Decision::Deny), Some(Mode::Enforce)));
    assert_eq!(scope.release.as_deref(), Some("support-agent"));
    assert_eq!(scope.release_digest.as_deref(), Some(release.as_str()));
    assert_eq!(scope.policy_version, policy);
    assert_bound(scope, &r.entries);

    let undeclared = &r.events[1];
    assert_eq!(undeclared.kind, EventKind::DecisionDeny);
    assert_eq!((undeclared.reason.as_str(), undeclared.tool.as_deref(), undeclared.path.as_deref()), ("undeclared_tool", Some("export_customers"), None));
    assert_bound(undeclared, &r.entries);
    assert_ne!(scope.fingerprint, undeclared.fingerprint);

    assert_eq!(r.events[0].to_json()["schema"], EVENT_SCHEMA);
    assert_no_values(&r.events, &["attacker@evil.example", "T-1042", "Customer list", "every customer", "everyone", "done"]);

    // The same failure in another run: the same fingerprint.
    let again = tempfile::tempdir().unwrap();
    let r2 = run_steps(again.path(), support_gate(GateMode::Enforce, again.path()), false, &[(call(7, "send_email", injected_email()), 1)]);
    assert_eq!(r2.events.len(), 1);
    assert_eq!(r2.events[0].fingerprint, scope.fingerprint);
}

#[test]
fn approval_required_emits_approval_requested_and_a_bad_receipt_approval_mismatch() {
    let refund = json!({"ticket_id": "T-1042", "amount": 350});
    let dir = tempfile::tempdir().unwrap();
    let r = run_steps(dir.path(), support_gate(GateMode::Enforce, dir.path()), false, &[(call(1, "issue_refund", refund.clone()), 1)]);
    assert_eq!(r.messages[0]["error"]["data"]["reason"], "approval_required", "{:?}", r.messages);
    assert_eq!(r.events.len(), 1, "{:#?}", r.events);
    let e = &r.events[0];
    assert_eq!((e.kind, e.reason.as_str(), e.decision), (EventKind::ApprovalRequested, "approval_required", Some(Decision::RequireApproval)));
    assert_bound(e, &r.entries);
    assert_no_values(&r.events, &["350", "T-1042"]);

    // A receipt for this exact call that is not a valid receipt.
    let dir = tempfile::tempdir().unwrap();
    let approvals = dir.path().join("approvals");
    std::fs::create_dir(&approvals).unwrap();
    let gate = support_gate(GateMode::Enforce, dir.path()).with_approvals(&approvals, vec![]);
    let fp = gate.approval_request("issue_refund", Some(&refund)).unwrap().fingerprint;
    std::fs::write(approvals.join(format!("{}.approval.json", fp.trim_start_matches("sha256:"))), b"{\"not\": \"a receipt\"}").unwrap();
    let r = run_steps(dir.path(), gate, false, &[(call(1, "issue_refund", refund), 1)]);
    assert_eq!(r.messages[0]["error"]["data"]["reason"], "approval_invalid", "{:?}", r.messages);
    assert_eq!(r.events.len(), 1, "{:#?}", r.events);
    assert_eq!((r.events[0].kind, r.events[0].decision), (EventKind::ApprovalMismatch, Some(Decision::Deny)));
    assert_bound(&r.events[0], &r.entries);
}

#[test]
fn shadow_mode_forwards_a_would_deny_and_emits_shadow_finding() {
    let dir = tempfile::tempdir().unwrap();
    let r = run_steps(
        dir.path(),
        support_gate(GateMode::Shadow, dir.path()),
        false,
        &[(call(1, "export_customers", json!({"filter": "everyone"})), 1), (call(2, "read_ticket", json!({"ticket_id": "T-1042"})), 2)],
    );
    assert!(r.seen.contains("export_customers"), "shadow forwards: {}", r.seen);
    assert!(r.messages.iter().all(|m| m.get("error").is_none()), "{:?}", r.messages);
    assert_eq!(r.events.len(), 1, "{:#?}", r.events);
    let e = &r.events[0];
    assert_eq!((e.kind, e.reason.as_str(), e.decision, e.mode), (EventKind::ShadowFinding, "undeclared_tool", Some(Decision::Deny), Some(Mode::Shadow)));
    assert_bound(e, &r.entries);
    assert_no_values(&r.events, &["everyone"]);
}

#[test]
fn a_replayed_side_effect_emits_side_effect_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let r = run_steps(
        dir.path(),
        support_gate(GateMode::Enforce, dir.path()),
        false,
        &[(call(1, "send_email", customer_email()), 1), (call(2, "send_email", customer_email()), 2)],
    );
    assert_eq!(r.seen.lines().count(), 1, "the retry is not forwarded: {}", r.seen);
    assert_eq!(r.messages[1]["result"]["_meta"]["cloakpipe"]["replayed"], true, "{:?}", r.messages);
    assert_eq!(r.events.len(), 1, "{:#?}", r.events);
    let e = &r.events[0];
    assert_eq!((e.kind, e.tool.as_deref(), e.decision), (EventKind::SideEffectReplayed, Some("send_email"), Some(Decision::Allow)));
    assert!(e.operation_id.is_some());
    assert_bound(e, &r.entries);
    assert_no_values(&r.events, &["dana@customer.example", "fixed-in-7-days", "Your ticket", "done"]);
}

#[test]
fn a_lost_reply_emits_side_effect_unknown() {
    let dir = tempfile::tempdir().unwrap();
    let r = run_steps(dir.path(), support_gate(GateMode::Enforce, dir.path()), true, &[(call(1, "send_email", customer_email()), 0)]);
    assert_eq!(r.messages.len(), 1, "the agent is told: {:?}", r.messages);
    assert_eq!(r.messages[0]["error"]["data"]["reason"], "operation_unknown");
    assert_eq!(r.events.len(), 1, "{:#?}", r.events);
    let e = &r.events[0];
    assert_eq!((e.kind, e.reason.as_str(), e.tool.as_deref()), (EventKind::SideEffectUnknown, "operation_unknown", Some("send_email")));
    assert_eq!(e.operation_id.as_deref(), r.messages[0]["error"]["data"]["operationId"].as_str());
    assert_bound(e, &r.entries);
}
