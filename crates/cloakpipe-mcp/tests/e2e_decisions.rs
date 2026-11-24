//! Every gate decision appends one signed decision ledger entry
//! (`cloakpipe.decision/v1`): allowed, refused and approval-gated calls,
//! in enforce and shadow mode. The entries verify offline with the gate's
//! public key, carry no raw argument values, and a ledger that cannot be
//! written fails the call closed.

use cloakpipe_ledger::decision::{Decision, DecisionEntry, Event, Mode};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::{run_proxy_io, DecisionLog, GateMode, ProxyContext, ToolGate};
use cloakpipe_release::contract::ToolContract;
use cloakpipe_release::{parse_path, AgentRelease, ArtifactRef, Format};
use serde_json::{json, Value};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

/// A fake tool that records every line and answers each with an empty result.
fn fake_upstream(dir: &Path) -> (Vec<String>, PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  id=$(printf '%s' "$line" | sed 's/^{{"id":\([0-9]*\),.*$/\1/')
  printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[]}}}}\n' "$id"
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (vec!["sh".into(), script.to_string_lossy().into_owned()], received)
}

/// support-agent@184: declares `refund` and `lookup-customer`.
fn support_gate(mode: GateMode) -> ToolGate {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    let m: AgentRelease = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    ToolGate::new(mode, &m).with_contracts(vec![], Some(json!({"taskId": "t-981"}))).unwrap()
}

fn example(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/action-boundary").join(name)
}

/// The action-boundary release with crm.patch needing an approval receipt
/// (operation tracking off).
fn approval_gate(mode: GateMode) -> ToolGate {
    let src = std::fs::read_to_string(example("crm-tools.contract.yaml")).unwrap().replace("sideEffect: true", "sideEffect: false");
    let c = ToolContract::parse_str(&src, Format::Yaml).unwrap();
    let mut m = parse_path(&example("release.yaml")).unwrap();
    m.spec.policies.retain(|p| !p.reference.starts_with("policy:tool-contract/"));
    m.spec.policies.push(ArtifactRef { reference: c.policy_ref() });
    let task: Value = serde_json::from_str(&std::fs::read_to_string(example("task-context.json")).unwrap()).unwrap();
    ToolGate::new(mode, &m).with_contracts(vec![c], Some(task)).unwrap()
}

fn call(id: u64, tool: &str, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}).to_string()
}

const KEY: [u8; 32] = [42; 32];

struct Run {
    messages: Vec<Value>,
    seen: String,
    entries: Vec<DecisionEntry>,
    release: String,
}

/// Run the proxy with a decision ledger; `sabotage` runs on the ledger
/// database after it is opened.
fn run(gate: ToolGate, lines: &[String], sabotage: Option<&str>) -> Run {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = fake_upstream(dir.path());
    let ledger_db = dir.path().join("ledger.db");
    let release = gate.release().to_string();
    let decisions = DecisionLog::open(ledger_db.to_str().unwrap(), GateKey::from_seed(KEY)).unwrap();
    if let Some(sql) = sabotage {
        rusqlite::Connection::open(&ledger_db).unwrap().execute_batch(sql).unwrap();
    }
    let ctx = ProxyContext { pii: None, ledger_db: None, release: None, gate: Some(gate), decisions: Some(decisions), events: Vec::new(), capture: None };
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(upstream, ctx, input, out.clone()).unwrap();
    let entries = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap().decisions().unwrap();
    Run { messages: out.messages(), seen: std::fs::read_to_string(&received).unwrap_or_default(), entries, release }
}

fn verify(entries: &[DecisionEntry]) -> cloakpipe_verify::decisions::DecisionSummary {
    let values: Vec<Value> = entries.iter().map(|e| serde_json::to_value(e).unwrap()).collect();
    cloakpipe_verify::decisions::verify_decisions(&values, &[GateKey::from_seed(KEY).public_key()]).expect("entries verify offline")
}

#[test]
fn every_decision_is_one_signed_entry() {
    let lines = [
        call(1, "refund", json!({"amount": 31337, "ticket": "T-5521"})),
        call(2, "export_customers", json!({"filter": "everyone"})),
        "{not json".to_string(),
    ];
    let r = run(support_gate(GateMode::Enforce), &lines, None);
    assert!(r.seen.contains("\"refund\"") && !r.seen.contains("export_customers"), "{}", r.seen);
    assert_eq!(r.entries.len(), 3, "{:#?}", r.entries);

    let allow = &r.entries[0];
    assert_eq!((allow.event, allow.decision, allow.reason.as_str()), (Event::Call, Decision::Allow, "ok"));
    assert_eq!(allow.tool.as_deref(), Some("refund"));
    assert_eq!(allow.release.as_deref(), Some(r.release.as_str()));
    assert_eq!(allow.policy_version.as_deref(), Some(r.release.as_str()), "the manifest digest, for now");
    assert_eq!(allow.mode, Some(Mode::Enforce));
    assert_eq!(allow.task_id.as_deref(), Some("t-981"));
    assert!(allow.forwarded);
    assert_eq!(allow.outcome, None);
    let fp = allow.args_fingerprint.as_deref().expect("the call's fingerprint");
    assert!(fp.starts_with("hmac-sha256:"), "{fp}");

    let deny = &r.entries[1];
    assert_eq!((deny.decision, deny.reason.as_str()), (Decision::Deny, "undeclared_tool"));
    assert_eq!(deny.tool.as_deref(), Some("export_customers"));
    assert!(!deny.forwarded);
    assert_ne!(deny.args_fingerprint, allow.args_fingerprint);

    let unreadable = &r.entries[2];
    assert_eq!((unreadable.decision, unreadable.reason.as_str(), unreadable.tool.as_deref()), (Decision::Deny, "unreadable", None));

    let s = verify(&r.entries);
    assert_eq!((s.entries, s.allowed, s.denied), (3, 1, 2));

    // Hashes and signatures are random-looking hex that can contain
    // "31337" by chance; every other field is checked.
    let mut values = serde_json::to_value(&r.entries).unwrap();
    for e in values.as_array_mut().unwrap() {
        for hex_field in ["entry_hash", "prev_hash", "sig", "args_fingerprint", "release", "policy_version", "signer"] {
            e.as_object_mut().unwrap().remove(hex_field);
        }
    }
    let dump = values.to_string();
    for raw in ["31337", "T-5521", "everyone"] {
        assert!(!dump.contains(raw), "{raw} reached the ledger: {dump}");
    }
}

#[test]
fn a_call_needing_approval_is_recorded_as_require_approval() {
    let args = json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified"}});
    let r = run(approval_gate(GateMode::Enforce), &[call(1, "crm.patch", args)], None);
    assert!(!r.seen.contains("crm.patch"));
    assert_eq!(r.entries.len(), 1);
    assert_eq!((r.entries[0].decision, r.entries[0].reason.as_str()), (Decision::RequireApproval, "approval_required"));
    assert_eq!(verify(&r.entries).approvals_required, 1);
}

#[test]
fn shadow_mode_forwards_and_records_what_enforce_would_have_decided() {
    let r = run(support_gate(GateMode::Shadow), &[call(1, "export_customers", json!({})), call(2, "refund", json!({}))], None);
    assert!(r.seen.contains("export_customers"), "shadow forwards: {}", r.seen);
    assert!(r.messages.iter().all(|m| m.get("error").is_none()), "{:?}", r.messages);
    assert_eq!(r.entries.len(), 2);
    let e = &r.entries[0];
    assert_eq!((e.decision, e.reason.as_str(), e.mode, e.forwarded), (Decision::Deny, "undeclared_tool", Some(Mode::Shadow), true));
    assert_eq!((r.entries[1].decision, r.entries[1].mode), (Decision::Allow, Some(Mode::Shadow)));
    assert_eq!(verify(&r.entries).shadow, 2);

    let args = json!({"tenant": "demo-co", "record": "lead-42", "patch": {"stage": "qualified"}});
    let r = run(approval_gate(GateMode::Shadow), &[call(1, "crm.patch", args)], None);
    assert!(r.seen.contains("crm.patch"));
    assert_eq!((r.entries[0].decision, r.entries[0].forwarded), (Decision::RequireApproval, true));
}

#[test]
fn a_ledger_write_failure_fails_the_call_closed() {
    let refuse = "CREATE TRIGGER full BEFORE INSERT ON decisions BEGIN SELECT RAISE(ABORT, 'disk full'); END;";
    for mode in [GateMode::Enforce, GateMode::Shadow] {
        let r = run(support_gate(mode), &[call(1, "refund", json!({"amount": 5})), call(2, "export_customers", json!({}))], Some(refuse));
        assert!(!r.seen.contains("tools/call"), "{mode:?}: nothing is forwarded without its record: {}", r.seen);
        for id in [1, 2] {
            let m = r.messages.iter().find(|m| m["id"] == id).expect("the agent is answered");
            assert_eq!(m["error"]["code"], -32001, "{m}");
            assert_eq!(m["error"]["data"]["reason"], "fail_closed", "{m}");
        }
        assert!(r.entries.is_empty());
    }
}

#[test]
fn other_messages_are_not_decisions() {
    let lines = [json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).to_string()];
    let r = run(support_gate(GateMode::Enforce), &lines, None);
    assert!(r.seen.contains("tools/list"));
    assert!(r.entries.is_empty(), "{:?}", r.entries);
}

/// A v1 manifest whose Cedar policy permits `read_ticket` and forbids
/// `send_email`, with its counters in `dir`.
fn cedar_gate(dir: &Path) -> ToolGate {
    std::fs::write(
        dir.join("support.cedar"),
        "@id(\"reads\")\npermit (principal, action == Action::\"read_ticket\", resource);\n\n\
         @id(\"no-email\")\nforbid (principal, action == Action::\"send_email\", resource);\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("cloakpipe.manifest.yaml"),
        "release: support-agent\nversion: 2026.10.3\npolicy: ./support.cedar\ntools:\n  \
         read_ticket:\n    args:\n      ticket_id: { type: string, required: true }\n  \
         send_email:\n    args:\n      to: { type: string, required: true }\n",
    )
    .unwrap();
    let m = cloakpipe_release::v1::Manifest::parse_path(&dir.join("cloakpipe.manifest.yaml")).unwrap();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_policy(cloakpipe_mcp::Counters::open(dir.join("state.db")).unwrap())
        .unwrap();
    g.ready().unwrap();
    g
}

#[test]
fn entries_carry_the_policy_digest_when_a_policy_is_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let gate = cedar_gate(dir.path());
    let digest = gate.policy_digest().expect("the manifest names a policy");
    let lines = [call(1, "read_ticket", json!({"ticket_id": "T-1"})), call(2, "send_email", json!({"to": "a@b.example"}))];
    let r = run(gate, &lines, None);
    assert_eq!(r.entries.len(), 2, "{:#?}", r.entries);
    assert_eq!((r.entries[0].decision, r.entries[1].reason.as_str()), (Decision::Allow, "policy_denied"));
    for e in &r.entries {
        assert_eq!(e.policy_digest.as_deref(), Some(digest.as_str()), "{e:#?}");
        assert_eq!(e.policy_version.as_deref(), Some(r.release.as_str()), "still the manifest digest");
    }
    verify(&r.entries);

    // Without a policy there is no policy digest to record.
    let r = run(support_gate(GateMode::Enforce), &[call(1, "refund", json!({"amount": 5}))], None);
    assert_eq!(r.entries[0].policy_digest, None);
}
