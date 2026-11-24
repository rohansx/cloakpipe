//! The interceptor enforces the tool gate: refused calls never reach the
//! upstream tool, the agent gets a JSON-RPC error for them, and the refusal
//! is a signed decision entry bound to the release.

use cloakpipe_ledger::decision::{Decision, DecisionEntry, Mode};
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::{run_proxy_io, DecisionLog, GateMode, ProxyContext, ToolGate};
use cloakpipe_release::AgentRelease;
use serde_json::{json, Value};
use std::io::{Cursor, Write};
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
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

/// A fake tool that records every line and answers each with an empty
/// result carrying the request's id.
fn fake_upstream(dir: &std::path::Path) -> (Vec<String>, std::path::PathBuf) {
    let received = dir.join("received.jsonl");
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  id=$(printf '%s' "$line" | grep -o '"id":[0-9]*' | head -n 1 | cut -d: -f2)
  printf '{{"id":%s,"jsonrpc":"2.0","result":{{"content":[]}}}}\n' "$id"
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (vec!["sh".into(), script.to_string_lossy().into_owned()], received)
}

fn manifest() -> AgentRelease {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// A gate over the release manifest alone (no certification).
fn manifest_gate(mode: GateMode) -> ToolGate {
    ToolGate::new(mode, &manifest())
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"q": "x"}}}).to_string()
}

fn run(gate: ToolGate, lines: &[String]) -> (Capture, String, Vec<DecisionEntry>, String) {
    let dir = tempfile::tempdir().unwrap();
    let (upstream, received) = fake_upstream(dir.path());
    let ledger_db = dir.path().join("ledger.db");
    let release = gate.release().to_string();
    let ctx = ProxyContext {
        pii: None,
        ledger_db: None,
        release: Some(gate.release_bytes()),
        gate: Some(gate),
        decisions: Some(DecisionLog::open(ledger_db.to_str().unwrap(), GateKey::from_seed([1; 32])).unwrap()),
        events: Vec::new(),
        capture: None,
    };
    let out = Capture::default();
    let input = Cursor::new(lines.iter().map(|l| format!("{l}\n")).collect::<String>().into_bytes());
    run_proxy_io(upstream, ctx, input, out.clone()).unwrap();
    let seen = std::fs::read_to_string(&received).unwrap_or_default();
    let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
    let records = store.decisions().unwrap();
    (out, seen, records, release)
}

#[test]
fn refused_calls_never_reach_the_tool() {
    let lines = [call(1, "refund"), call(2, "delete_customer"), json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).to_string()];
    let (out, seen, records, release) = run(manifest_gate(GateMode::Enforce), &lines);

    assert!(seen.contains("\"refund\""), "the declared tool was called: {seen}");
    assert!(!seen.contains("delete_customer"), "the refused call reached the tool: {seen}");
    assert!(seen.contains("tools/list"), "other methods pass through: {seen}");

    let msgs = out.messages();
    let refusal = msgs.iter().find(|m| m["id"] == 2).expect("the agent gets an answer for the refused call");
    assert_eq!(refusal["error"]["code"], -32001);
    assert_eq!(refusal["error"]["data"]["reason"], "undeclared_tool");
    assert_eq!(refusal["error"]["data"]["tool"], "delete_customer");
    assert!(refusal.get("result").is_none());
    assert!(msgs.iter().any(|m| m["id"] == 1 && m.get("result").is_some()), "{msgs:?}");

    let blocks: Vec<_> = records.iter().filter(|r| r.decision == Decision::Deny).collect();
    assert_eq!(blocks.len(), 1, "{records:?}");
    assert_eq!(blocks[0].release.as_deref(), Some(release.as_str()));
    assert_eq!(blocks[0].reason, "undeclared_tool");
    assert!(!blocks[0].forwarded);
    assert!(records.iter().any(|r| r.decision == Decision::Allow && r.tool.as_deref() == Some("refund") && r.forwarded));
}

#[test]
fn shadow_mode_forwards_and_records_the_violation() {
    let (out, seen, records, _) = run(manifest_gate(GateMode::Shadow), &[call(2, "delete_customer")]);
    assert!(seen.contains("delete_customer"), "shadow mode forwards: {seen}");
    assert!(out.messages().iter().all(|m| m.get("error").is_none()));
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!((records[0].decision, records[0].reason.as_str()), (Decision::Deny, "undeclared_tool"));
    assert_eq!((records[0].mode, records[0].forwarded), (Some(Mode::Shadow), true));
}

#[test]
fn a_refused_call_without_an_id_gets_no_reply() {
    // JSON-RPC notifications have no id and take no response.
    let note = json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "delete_customer"}}).to_string();
    let (out, seen, _, _) = run(manifest_gate(GateMode::Enforce), &[note]);
    assert!(!seen.contains("delete_customer"));
    assert!(out.messages().is_empty());
}

// ── fail closed on anything the gate cannot read (review findings) ──────

/// Lines an agent could use to slip a refused call past a gate that only
/// understands well-formed, canonical JSON objects. Each must be refused,
/// never forwarded.
fn smuggling_attempts() -> Vec<(&'static str, String)> {
    let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
    vec![
        ("batch", format!("[{}]", call(9, "delete_customer"))),
        ("number out of range", r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_customer","arguments":{"x":1e400}}}"#.into()),
        ("lone surrogate", r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"delete_customer","arguments":{"x":"\ud800"}}}"#.into()),
        ("deep nesting", format!(r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"delete_customer","arguments":{{"x":{deep}}}}}}}"#)),
        ("carriage return", format!("{}\r{}", json!({"jsonrpc": "2.0", "id": 8, "method": "ping"}), call(9, "delete_customer"))),
        ("case-variant method key", r#"{"jsonrpc":"2.0","id":9,"Method":"tools/call","params":{"name":"delete_customer","arguments":{}}}"#.into()),
        ("case-variant name key", r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"Name":"delete_customer","arguments":{}}}"#.into()),
        ("not an object", r#""tools/call delete_customer""#.into()),
        ("unicode-folded key", "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/call\",\"param\u{17F}\":{\"name\":\"delete_customer\"}}".into()),
    ]
}

#[test]
fn unreadable_or_noncanonical_messages_are_refused_not_forwarded() {
    for (what, line) in smuggling_attempts() {
        let (out, seen, records, _) = run(manifest_gate(GateMode::Enforce), std::slice::from_ref(&line));
        assert!(!seen.contains("delete_customer"), "{what}: forwarded to the tool: {seen}");
        let msgs = out.messages();
        assert_eq!(msgs.len(), 1, "{what}: one error back to the agent: {msgs:?}");
        assert!(msgs[0]["error"]["code"].as_i64().is_some(), "{what}: {msgs:?}");
        assert!(records.iter().any(|r| r.decision == Decision::Deny && !r.forwarded), "{what}: the refusal is evidence");
    }
}

#[test]
fn shadow_mode_does_not_forward_what_it_cannot_read_either() {
    // Shadow mode reports policy violations, but a message the gate cannot
    // check is never forwarded unchecked.
    let (_, seen, _, _) = run(manifest_gate(GateMode::Shadow), &[format!("[{}]", call(9, "delete_customer"))]);
    assert!(!seen.contains("delete_customer"), "{seen}");
}

#[test]
fn a_refused_request_with_a_null_id_is_answered() {
    let line = json!({"jsonrpc": "2.0", "id": null, "method": "tools/call", "params": {"name": "delete_customer"}}).to_string();
    let (out, seen, _, _) = run(manifest_gate(GateMode::Enforce), &[line]);
    assert!(!seen.contains("delete_customer"));
    let msgs = out.messages();
    assert_eq!(msgs.len(), 1, "{msgs:?}");
    assert!(msgs[0]["id"].is_null() && msgs[0]["error"]["data"]["reason"] == "undeclared_tool", "{msgs:?}");
}

#[test]
fn ordinary_messages_still_flow_with_a_gate() {
    let lines = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}).to_string(),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string(),
        call(2, "refund"),
    ];
    let (_, seen, _, _) = run(manifest_gate(GateMode::Enforce), &lines);
    for needle in ["initialize", "notifications/initialized", "\"refund\""] {
        assert!(seen.contains(needle), "{needle}: {seen}");
    }
}
