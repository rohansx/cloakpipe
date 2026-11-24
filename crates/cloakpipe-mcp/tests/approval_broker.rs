//! Approvals through a broker ([`cloakpipe_mcp::broker`]): a call refused
//! as `approval_required` files a signed request with only the manifest's
//! `approval.show` values; a background poller fetches finished receipts,
//! verifies each locally against the trusted approver keys and only then
//! writes it into the approvals directory, where the agent's retry finds it.
//! The decision path never waits on the network. Against a stub broker on
//! 127.0.0.1 that signs receipts with `cloakpipe-receipt`.

#[path = "support/broker.rs"]
mod broker;
#[path = "support/receiver.rs"]
mod receiver;

use broker::{rfc3339, StubBroker};
use cloakpipe_ledger::decision::Decision;
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::broker::{ApprovalBroker, BrokerConfig, RequestStatus, REQUEST_SCHEMA};
use cloakpipe_mcp::events::webhook::verify_signature;
use cloakpipe_mcp::{Action, DecisionLog, Denial, EventKind, EventSink, GateEvent, GateMode, Interceptor, ProxyContext, ToolGate};
use cloakpipe_receipt::dsse::TrustedKey;
use cloakpipe_release::v1::Manifest;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SECRET: &[u8] = b"gate-secret-0123456789";
const WAIT: Duration = Duration::from_secs(10);
const KEYID: &str = "ed25519:approver-test-1";

/// Example 3: refunds over 100 need a signed approval for that exact call;
/// a broker may see the amount, nothing else.
const MANIFEST: &str = r#"
release: refunds
version: "3"
tools:
  issue_refund:
    args:
      ticket_id: { type: string, one_of_context: ["ticket.id"], required: true }
      amount: { type: integer, min: 0, max: 5000, required: true }
      note: { type: string, max_len: 200 }
    approval: { when: "amount > 100", approvers: ["slack:#support-leads"], ttl: 15m, show: [amount] }
"#;

/// Argument values a broker must never see.
const PRIVATE: &[&str] = &["T-1042", "customer-private-note"];

fn approver() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn trusted() -> Vec<TrustedKey> {
    vec![TrustedKey { keyid: KEYID.into(), public_key: approver().verifying_key().to_bytes() }]
}

fn refund(amount: u64) -> Value {
    json!({"ticket_id": "T-1042", "amount": amount, "note": "customer-private-note"})
}

fn call(id: u64, arguments: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": "issue_refund", "arguments": arguments}}).to_string()
}

fn gate(approvals: &Path) -> ToolGate {
    let m = Manifest::parse_str(MANIFEST, Path::new(".")).unwrap();
    ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_task_context(Some(json!({"taskId": "t-981", "ticket": {"id": "T-1042"}})))
        .unwrap()
        .with_approvals(approvals, trusted())
}

fn config(url: &str) -> BrokerConfig {
    let mut cfg = BrokerConfig::new(url, SECRET.to_vec());
    cfg.timeout = Duration::from_millis(500);
    cfg.backoff = Duration::from_millis(10);
    cfg
}

/// A sink that keeps every event.
#[derive(Default)]
struct Recorder(Mutex<Vec<GateEvent>>);

impl EventSink for Recorder {
    fn emit(&self, event: &GateEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

struct Setup {
    stub: StubBroker,
    broker: Arc<ApprovalBroker>,
    gate: Interceptor,
    events: Arc<Recorder>,
    approvals: PathBuf,
    ledger: PathBuf,
    release: String,
    _dir: tempfile::TempDir,
}

fn setup() -> Setup {
    let stub = StubBroker::start(SECRET);
    setup_with(stub, None)
}

fn setup_with(stub: StubBroker, url: Option<String>) -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let approvals = dir.path().join("approvals");
    std::fs::create_dir(&approvals).unwrap();
    let events = Arc::new(Recorder::default());
    let g = gate(&approvals);
    let release = g.release().to_string();
    let broker = ApprovalBroker::manual(config(&url.unwrap_or_else(|| stub.url())), &g, vec![events.clone()]).unwrap();
    let g = g.with_broker(broker.clone());
    let ledger = dir.path().join("ledger.db");
    let ctx = ProxyContext {
        pii: None,
        ledger_db: None,
        release: None,
        gate: Some(g),
        decisions: Some(DecisionLog::open(ledger.to_str().unwrap(), GateKey::from_seed([9; 32])).unwrap()),
        events: vec![events.clone()],
        capture: None,
    };
    let gate = Interceptor::new(ctx).unwrap();
    Setup { stub, broker, gate, events, approvals, ledger, release, _dir: dir }
}

/// The agent's reply among `actions`, if the call was answered.
fn reply(actions: &[Action]) -> Option<Value> {
    actions.iter().find_map(|a| match a {
        Action::ToAgent(line) => Some(serde_json::from_str(line).unwrap()),
        _ => None,
    })
}

fn forwarded(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::ToUpstream { .. }))
}

fn data(actions: &[Action]) -> Value {
    reply(actions).unwrap_or_else(|| panic!("no reply: {actions:?}"))["error"]["data"].clone()
}

fn receipt_path(approvals: &Path, fingerprint: &str) -> PathBuf {
    approvals.join(format!("{}.approval.json", fingerprint.trim_start_matches("sha256:")))
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

/// Refuse one call as approval_required and wait for its request: the fingerprint.
fn requested(s: &Setup, id: u64, amount: u64) -> String {
    let before = s.stub.posts().len();
    let d = data(&s.gate.on_agent_line(&call(id, refund(amount))));
    assert_eq!(d["reason"], "approval_required", "{d}");
    let posts = s.stub.wait_for_posts(before + 1, WAIT);
    assert_eq!(posts.len(), before + 1, "one request filed");
    assert!(s.broker.flush(WAIT));
    d["fingerprint"].as_str().unwrap().to_string()
}

// ── the request ─────────────────────────────────────────────────────────

#[test]
fn a_refused_call_files_a_signed_request_with_only_the_shown_values() {
    let s = setup();
    let d = data(&s.gate.on_agent_line(&call(1, refund(350))));
    assert_eq!(d["reason"], "approval_required");
    assert_eq!(d["approval_request"], "requested", "{d}");
    assert!(d["hint"].as_str().unwrap().contains("retry"), "{d}");
    let fp = d["fingerprint"].as_str().unwrap().to_string();

    let posts = s.stub.wait_for_posts(1, WAIT);
    assert_eq!(posts.len(), 1);
    let post = &posts[0];
    assert!(post.signed, "signed with the gate's secret");
    assert_eq!(post.target, "/v1/gates/g-test-1/approvals");
    assert_eq!(post.headers.get("content-type").map(String::as_str), Some("application/json"));
    let header = &post.headers["cloakpipe-signature"];
    verify_signature(SECRET, header, &post.body, chrono::Utc::now().timestamp(), Some(300)).unwrap();

    let req = post.json();
    assert_eq!(req["schema"], REQUEST_SCHEMA);
    assert_eq!(req["fingerprint"], fp.as_str());
    assert_eq!(req["tool"], "issue_refund");
    assert_eq!(req["approvers"], json!(["slack:#support-leads"]));
    assert_eq!((req["release"].as_str(), req["version"].as_str()), (Some("refunds"), Some("3")));
    assert_eq!(req["release_digest"], s.release.as_str());
    assert_eq!(req["task_id"], "t-981");
    assert_eq!(req["ttl_secs"], 900);
    // Only what the manifest opts in to showing.
    assert_eq!(req["shown"], json!({"amount": 350}));
    for v in PRIVATE {
        assert!(!post.text().contains(v), "{v} reached the broker: {}", post.text());
    }
    // The decision ledger entry the refusal is.
    let entries = LedgerStore::open(s.ledger.to_str().unwrap()).unwrap().decisions().unwrap();
    let entry = entries.iter().find(|e| e.reason == "approval_required").expect("recorded");
    assert_eq!(req["ledger_seq"], entry.seq);
    let requested_at = chrono::DateTime::parse_from_rfc3339(req["requested_at"].as_str().unwrap()).unwrap();
    let expires_at = chrono::DateTime::parse_from_rfc3339(req["expires_at"].as_str().unwrap()).unwrap();
    assert_eq!((expires_at - requested_at).num_seconds(), 900);
    let mut members: Vec<&String> = req.as_object().unwrap().keys().collect();
    members.sort();
    assert_eq!(
        members,
        ["approvers", "expires_at", "fingerprint", "ledger_seq", "release", "release_digest", "requested_at", "schema", "shown", "task_id", "tool", "ttl_secs", "version"]
    );
}

#[test]
fn a_call_that_needs_no_approval_files_nothing() {
    let s = setup();
    assert!(forwarded(&s.gate.on_agent_line(&call(1, refund(50)))));
    assert!(s.broker.flush(WAIT));
    std::thread::sleep(Duration::from_millis(100));
    assert!(s.stub.posts().is_empty());
}

#[test]
fn a_retry_before_the_decision_files_no_second_request() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_required"), Some("pending")), "{d}");
    assert!(s.broker.flush(WAIT));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(s.stub.posts().len(), 1);
    assert_eq!(s.stub.request(&fp).unwrap()["fingerprint"], fp.as_str());
}

#[test]
fn the_decision_never_waits_on_the_broker() {
    let dead = receiver::black_hole();
    let s = setup_with(StubBroker::start(SECRET), Some(format!("{dead}/v1/gates/g-test-1")));
    for i in 0..5 {
        let started = Instant::now();
        let d = data(&s.gate.on_agent_line(&call(i, refund(350 + i))));
        assert!(started.elapsed() < Duration::from_millis(300), "the decision waited {:?}", started.elapsed());
        assert_eq!(d["reason"], "approval_required");
    }
    // A poll against a dead broker fails; nothing is written.
    assert!(s.broker.poll_once().is_err());
    assert!(files(&s.approvals).is_empty());
}

// ── the poller ──────────────────────────────────────────────────────────

#[test]
fn example_3_an_approved_receipt_is_fetched_and_the_retry_is_forwarded() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    let envelope = s.stub.approve(&fp, &approver(), KEYID);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    let path = receipt_path(&s.approvals, &fp);
    let written: Value = serde_json::from_slice(&std::fs::read(&path).expect("receipt written")).unwrap();
    assert_eq!(written, envelope);
    assert_eq!(files(&s.approvals), [format!("{}.approval.json", fp.trim_start_matches("sha256:"))], "no temporary file left");

    // The agent retries the same call: forwarded on the receipt.
    assert!(forwarded(&s.gate.on_agent_line(&call(2, refund(350)))));
    let entries = LedgerStore::open(s.ledger.to_str().unwrap()).unwrap().decisions().unwrap();
    let allowed = entries.iter().find(|e| e.decision == Decision::Allow).expect("an allow");
    assert!(allowed.approval.is_some(), "the receipt is recorded: {allowed:?}");

    // Reusing it for $3,500 is another call: approval_required, a new request.
    let d = data(&s.gate.on_agent_line(&call(3, refund(3500))));
    assert_eq!(d["reason"], "approval_required");
    assert_ne!(d["fingerprint"], fp.as_str());
    assert_eq!(s.stub.wait_for_posts(2, WAIT).len(), 2);

    // Polls are signed over "GET <target>" and carry the cursor.
    let polls = s.stub.polls();
    assert!(polls.iter().all(|p| p.signed), "{polls:?}");
    assert_eq!(polls[0].target, "/v1/gates/g-test-1/approvals");
    assert_eq!(s.broker.poll_once().unwrap(), 0);
    assert_eq!(s.stub.polls().last().unwrap().target, "/v1/gates/g-test-1/approvals?since=c-1");
}

#[test]
fn a_receipt_that_does_not_verify_is_not_written_and_raises_approval_mismatch() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    // Signed by a key the gate does not trust.
    s.stub.approve(&fp, &SigningKey::from_bytes(&[8u8; 32]), KEYID);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    assert!(!receipt_path(&s.approvals, &fp).exists());
    let events = s.events.0.lock().unwrap().clone();
    let mismatch: Vec<&GateEvent> = events.iter().filter(|e| e.kind == EventKind::ApprovalMismatch).collect();
    assert_eq!(mismatch.len(), 1, "{events:#?}");
    assert_eq!((mismatch[0].reason.as_str(), mismatch[0].tool.as_deref()), ("approval_invalid", Some("issue_refund")));
    assert_eq!(mismatch[0].release_digest.as_deref(), Some(s.release.as_str()));
    // Still approval_required.
    assert_eq!(data(&s.gate.on_agent_line(&call(2, refund(350))))["reason"], "approval_required");

    // A valid receipt for $3,500 reported as the $350 call's.
    let other = requested(&s, 3, 3500);
    let envelope = s.stub.approve(&other, &approver(), KEYID);
    s.stub.finish(json!({"request_id": "r-x", "fingerprint": fp, "status": "approved", "envelope": envelope}));
    assert_eq!(s.broker.poll_once().unwrap(), 2);
    assert!(receipt_path(&s.approvals, &other).exists(), "the genuine one is written");
    assert!(!receipt_path(&s.approvals, &fp).exists(), "the swapped one is not");
    let n = s.events.0.lock().unwrap().iter().filter(|e| e.kind == EventKind::ApprovalMismatch).count();
    assert_eq!(n, 2);
}

#[test]
fn a_receipt_longer_than_the_ttl_or_expired_is_not_written() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    // Valid for an hour: longer than the tool's 15m ttl.
    s.stub.approve_with(&fp, &approver(), KEYID, 0, 3600);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    assert!(!receipt_path(&s.approvals, &fp).exists());
    assert_eq!(s.events.0.lock().unwrap().iter().filter(|e| e.kind == EventKind::ApprovalMismatch).count(), 1);
    // Already expired: dropped quietly (it would be approval_expired anyway).
    s.stub.approve_with(&fp, &approver(), KEYID, -1000, 600);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    assert!(!receipt_path(&s.approvals, &fp).exists());
    assert_eq!(s.events.0.lock().unwrap().iter().filter(|e| e.kind == EventKind::ApprovalMismatch).count(), 1);
}

#[test]
fn a_record_with_a_bad_fingerprint_never_reaches_the_file_system() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    let envelope = s.stub.approve(&fp, &approver(), KEYID);
    std::fs::remove_file(receipt_path(&s.approvals, &fp)).ok();
    let hex = fp.trim_start_matches("sha256:");
    for bad in [
        "sha256:../../escape".to_string(),
        format!("sha256:{}", hex.to_ascii_uppercase()),
        hex.to_string(),
        format!("sha256:{hex}00"),
        format!("sha256:{}/x", &hex[..62]),
    ] {
        s.stub.finish(json!({"fingerprint": bad, "status": "approved", "envelope": envelope}));
        s.stub.finish(json!({"fingerprint": bad, "status": "denied"}));
    }
    s.stub.finish(json!({"fingerprint": fp, "status": "approved"}));
    s.stub.finish(json!({"fingerprint": fp, "status": "approved", "envelope": "not an envelope"}));
    s.stub.finish(json!({"fingerprint": fp, "status": "sideways"}));
    s.broker.poll_once().unwrap();
    assert_eq!(files(&s.approvals), [format!("{hex}.approval.json")], "only the genuine receipt");
    let parent = s.approvals.parent().unwrap();
    assert!(!parent.join("escape").exists() && !parent.parent().unwrap().join("escape").exists());
}

// ── denied and expired ──────────────────────────────────────────────────

#[test]
fn a_denied_call_is_refused_as_approval_denied_and_not_requested_again() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    s.stub.deny(&fp, None);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    let marker = s.approvals.join(format!("{}.denied.json", fp.trim_start_matches("sha256:")));
    let m: Value = serde_json::from_slice(&std::fs::read(&marker).expect("a denial marker")).unwrap();
    assert_eq!(m["fingerprint"], fp.as_str());
    assert_eq!(m["status"], "denied");

    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_denied"), Some("denied")), "{d}");
    assert!(s.broker.flush(WAIT));
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(s.stub.posts().len(), 1, "no new request for a denied call");
    let entries = LedgerStore::open(s.ledger.to_str().unwrap()).unwrap().decisions().unwrap();
    let last = entries.last().unwrap();
    assert_eq!((last.decision, last.reason.as_str()), (Decision::Deny, "approval_denied"));
    let events = s.events.0.lock().unwrap().clone();
    assert!(events.iter().any(|e| e.kind == EventKind::DecisionDeny && e.reason == "approval_denied"), "{events:#?}");
    // Another amount is another call.
    assert_eq!(data(&s.gate.on_agent_line(&call(3, refund(351))))["reason"], "approval_required");
}

#[test]
fn a_denial_lasts_until_its_not_after_then_the_call_can_be_requested_again() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    s.stub.deny(&fp, Some(&rfc3339(chrono::Utc::now() - chrono::Duration::seconds(5))));
    s.broker.poll_once().unwrap();
    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_required"), Some("requested")), "{d}");
    assert_eq!(s.stub.wait_for_posts(2, WAIT).len(), 2);
}

#[test]
fn an_expired_request_is_approval_required_again_and_filed_anew() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    s.stub.expire(&fp);
    assert_eq!(s.broker.poll_once().unwrap(), 1);
    assert!(files(&s.approvals).is_empty(), "nothing written for an expired request");
    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_required"), Some("requested")), "{d}");
    assert_eq!(s.stub.wait_for_posts(2, WAIT).len(), 2);
}

#[test]
fn a_broker_outage_changes_nothing_but_the_request_is_retried_later() {
    let s = setup();
    s.stub.fail_with(Some(503));
    let d = data(&s.gate.on_agent_line(&call(1, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_required"), Some("requested")));
    assert!(s.broker.flush(WAIT));
    assert!(s.broker.poll_once().is_err());
    assert!(files(&s.approvals).is_empty());
    // Back up: the next retry files the request again.
    s.stub.fail_with(None);
    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!(d["approval_request"], "requested", "{d}");
    assert!(s.broker.flush(WAIT));
    let fp = d["fingerprint"].as_str().unwrap();
    assert!(s.stub.request(fp).is_some(), "filed once the broker is back");
}

// ── the gate on its own ─────────────────────────────────────────────────

#[test]
fn a_denial_marker_refuses_the_call_until_its_not_after() {
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    let now = rfc3339(chrono::Utc::now());
    let fp = g.approval_request("issue_refund", Some(&refund(350))).unwrap().fingerprint;
    let marker = dir.path().join(format!("{}.denied.json", fp.trim_start_matches("sha256:")));
    let write = |not_after: chrono::DateTime<chrono::Utc>| {
        std::fs::write(&marker, json!({"fingerprint": fp, "status": "denied", "notAfter": rfc3339(not_after)}).to_string()).unwrap()
    };
    write(chrono::Utc::now() + chrono::Duration::minutes(10));
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Err(Denial::ApprovalDenied));
    assert_eq!(Denial::ApprovalDenied.code(), "approval_denied");
    // Another call is not covered.
    assert_eq!(g.check("issue_refund", Some(&refund(351)), &now), Err(Denial::ApprovalRequired));
    write(chrono::Utc::now() - chrono::Duration::minutes(1));
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Err(Denial::ApprovalRequired));
    std::fs::write(&marker, b"not json").unwrap();
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Err(Denial::ApprovalRequired));
}

#[test]
fn a_broker_needs_approvals_and_a_task_id() {
    let m = Manifest::parse_str(MANIFEST, Path::new(".")).unwrap();
    let url = "http://127.0.0.1:9/v1/gates/g";
    let bare = ToolGate::from_manifest(GateMode::Enforce, &m);
    assert!(ApprovalBroker::manual(config(url), &bare, vec![]).is_err(), "no approvals directory");
    let dir = tempfile::tempdir().unwrap();
    let no_task = ToolGate::from_manifest(GateMode::Enforce, &m).with_approvals(dir.path(), trusted());
    assert!(ApprovalBroker::manual(config(url), &no_task, vec![]).is_err(), "no taskId to sign");
    assert!(ApprovalBroker::manual(config("ftp://x"), &gate(dir.path()), vec![]).is_err(), "not http(s)");
    assert!(ApprovalBroker::manual(config(url), &gate(dir.path()), vec![]).is_ok());
    assert_eq!(RequestStatus::Requested.as_str(), "requested");
    assert_eq!(RequestStatus::Pending.as_str(), "pending");
    assert_eq!(RequestStatus::Denied.as_str(), "denied");
}

#[test]
fn the_background_poller_fetches_receipts_on_its_own() {
    let stub = StubBroker::start(SECRET);
    let dir = tempfile::tempdir().unwrap();
    let g = gate(dir.path());
    let mut cfg = config(&stub.url());
    cfg.poll_interval = Duration::from_millis(50);
    let b = ApprovalBroker::start(cfg, &g, vec![]).unwrap();
    let g = g.with_broker(b.clone());
    let now = rfc3339(chrono::Utc::now());
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Err(Denial::ApprovalRequired));
    assert_eq!(g.request_approval("issue_refund", Some(&refund(350)), Some(1)), Some(RequestStatus::Requested));
    let fp = g.approval_request("issue_refund", Some(&refund(350))).unwrap().fingerprint;
    assert_eq!(stub.wait_for_posts(1, WAIT).len(), 1);
    stub.approve(&fp, &approver(), KEYID);
    let deadline = Instant::now() + WAIT;
    while !receipt_path(dir.path(), &fp).exists() {
        assert!(Instant::now() < deadline, "the poller never wrote the receipt");
        std::thread::sleep(Duration::from_millis(20));
    }
    let now = rfc3339(chrono::Utc::now());
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Ok(()));
    b.stop();
}

#[test]
fn a_huge_ttl_or_a_far_denial_is_capped_not_a_panic() {
    let stub = StubBroker::start(SECRET);
    let dir = tempfile::tempdir().unwrap();
    let src = MANIFEST.replace("ttl: 15m", "ttl: 9999999999d");
    let m = Manifest::parse_str(&src, Path::new(".")).unwrap();
    let g = ToolGate::from_manifest(GateMode::Enforce, &m)
        .with_task_context(Some(json!({"taskId": "t-981", "ticket": {"id": "T-1042"}})))
        .unwrap()
        .with_approvals(dir.path(), trusted());
    let b = ApprovalBroker::manual(config(&stub.url()), &g, vec![]).unwrap();
    let g = g.with_broker(b.clone());
    assert_eq!(g.request_approval("issue_refund", Some(&refund(350)), None), Some(RequestStatus::Requested));
    assert_eq!(stub.wait_for_posts(1, WAIT).len(), 1);
    let fp = g.approval_request("issue_refund", Some(&refund(350))).unwrap().fingerprint;
    // A denial "until the year 9999" holds for at most a year.
    stub.deny(&fp, Some("9999-12-31T23:59:59Z"));
    b.poll_once().unwrap();
    let marker: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join(format!("{}.denied.json", fp.trim_start_matches("sha256:")))).unwrap()).unwrap();
    let until = chrono::DateTime::parse_from_rfc3339(marker["notAfter"].as_str().unwrap()).unwrap();
    assert!(until < chrono::Utc::now() + chrono::Duration::days(367), "{until}");
    let now = rfc3339(chrono::Utc::now());
    assert_eq!(g.check("issue_refund", Some(&refund(350)), &now), Err(Denial::ApprovalDenied));
}

// ── a gate shared by several processes (adversarial verification) ───────

/// A receipt signed for `task_id`, as a broker reports it for that task's
/// request of the call `fingerprint`.
fn record_for_task(s: &Setup, fingerprint: &str, task_id: &str, status: &str) -> Value {
    use cloakpipe_receipt::approval::{sign_approval, Approval};
    use cloakpipe_release::action::ToolCallFingerprint;
    let mut raw = [0u8; 32];
    hex::decode_to_slice(fingerprint.trim_start_matches("sha256:"), &mut raw).unwrap();
    let now = chrono::Utc::now();
    let mut record = json!({
        "request_id": format!("r-{task_id}"),
        "fingerprint": fingerprint,
        "task_id": task_id,
        "status": status,
        "decided_at": rfc3339(now),
    });
    if status == "approved" {
        let a = Approval {
            release: s.release.clone(),
            tool: "issue_refund".into(),
            task_id: task_id.into(),
            operation_id: uuid::Uuid::new_v4().to_string(),
            approver: KEYID.into(),
            approved_at: rfc3339(now),
            not_after: rfc3339(now + chrono::Duration::seconds(600)),
        };
        record["envelope"] = serde_json::to_value(sign_approval(&ToolCallFingerprint(raw), &a, &approver(), KEYID)).unwrap();
    } else {
        record["not_after"] = json!(rfc3339(now + chrono::Duration::seconds(600)));
    }
    record
}

/// Gate processes with different task contexts may share one gate at the
/// broker, and a poll returns the gate's finished requests whatever task
/// they were for. Another task's records are not about this process's
/// calls: its receipt (signed for the other task) is not a mismatch, and
/// its denial does not refuse this task's call.
#[test]
fn records_for_another_task_sharing_the_gate_are_skipped_quietly() {
    let s = setup();
    let fp = requested(&s, 1, 350);
    s.stub.finish(record_for_task(&s, &fp, "t-other", "approved"));
    s.stub.finish(record_for_task(&s, &fp, "t-other", "denied"));
    assert_eq!(s.broker.poll_once().unwrap(), 2);
    assert!(!receipt_path(&s.approvals, &fp).exists(), "another task's receipt is not written");
    assert!(files(&s.approvals).is_empty(), "nor a denial marker: {:?}", files(&s.approvals));
    let events = s.events.0.lock().unwrap().clone();
    assert!(!events.iter().any(|e| e.kind == EventKind::ApprovalMismatch), "not a mismatch: {events:#?}");
    let d = data(&s.gate.on_agent_line(&call(2, refund(350))));
    assert_eq!((d["reason"].as_str(), d["approval_request"].as_str()), (Some("approval_required"), Some("pending")), "{d}");

    // This task's own approval still arrives.
    s.stub.finish(record_for_task(&s, &fp, "t-981", "approved"));
    s.broker.poll_once().unwrap();
    assert!(receipt_path(&s.approvals, &fp).exists());
    assert!(forwarded(&s.gate.on_agent_line(&call(3, refund(350)))));
}
