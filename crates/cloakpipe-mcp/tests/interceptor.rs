//! The transport-agnostic interceptor ([`Interceptor`]), driven without any
//! process or stream: each message in, the actions out. The stdio runner
//! (`run_proxy_io`) is a thin loop over exactly this.

use cloakpipe_ledger::decision::Decision;
use cloakpipe_ledger::{GateKey, LedgerStore};
use cloakpipe_mcp::{Action, DecisionLog, GateMode, Interceptor, ProxyContext, ToolGate, Upstream, UpstreamTransport, DEFAULT_SERVER};
use cloakpipe_release::AgentRelease;
use serde_json::{json, Value};

/// support-agent@184: declares `refund` and `lookup-customer`.
fn support_gate() -> ToolGate {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../cloakpipe-release/testdata/support-agent-184.json");
    let m: AgentRelease = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    ToolGate::new(GateMode::Enforce, &m).with_contracts(vec![], Some(json!({"taskId": "t-981"}))).unwrap()
}

fn call(id: u64, tool: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": tool, "arguments": {"amount": 5}}}).to_string()
}

fn ctx(gate: Option<ToolGate>, decisions: Option<DecisionLog>) -> ProxyContext {
    ProxyContext { pii: None, ledger_db: None, release: None, gate, decisions, events: Vec::new(), capture: None }
}

fn agent_message(actions: &[Action]) -> Value {
    match actions {
        [Action::ToAgent(line)] => serde_json::from_str(line).unwrap(),
        other => panic!("expected one message for the agent: {other:?}"),
    }
}

#[test]
fn a_single_upstream_is_named_default() {
    let up = Upstream::stdio(DEFAULT_SERVER, vec!["mcp-server".into()]);
    assert_eq!(DEFAULT_SERVER, "default");
    assert_eq!(up.name, "default");
    assert_eq!(up.transport, UpstreamTransport::Stdio { command: vec!["mcp-server".into()] });
}

#[test]
fn decides_each_message_and_returns_what_to_send() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("ledger.db");
    let decisions = DecisionLog::open(db.to_str().unwrap(), GateKey::from_seed([5; 32])).unwrap();
    let i = Interceptor::new(ctx(Some(support_gate()), Some(decisions))).unwrap();

    // Allowed: forwarded to the default upstream, re-serialized.
    let actions = i.on_agent_line(&call(1, "refund"));
    let [Action::ToUpstream { server, message }] = actions.as_slice() else { panic!("{actions:?}") };
    assert_eq!(server, DEFAULT_SERVER);
    let forwarded: Value = serde_json::from_str(message).unwrap();
    assert_eq!(forwarded["params"]["name"], "refund");

    // Refused: answered to the agent, never forwarded.
    let refusal = agent_message(&i.on_agent_line(&call(2, "export_customers")));
    assert_eq!(refusal["id"], 2);
    assert_eq!(refusal["error"]["data"]["reason"], "undeclared_tool");

    // Unreadable: refused with a parse error.
    let unreadable = agent_message(&i.on_agent_line("{not json"));
    assert_eq!(unreadable["error"]["code"], -32700);

    // The upstream's reply goes to the agent.
    let reply = agent_message(&i.on_upstream_line(DEFAULT_SERVER, r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#));
    assert_eq!(reply["id"], 1);
    assert!(i.finish().is_empty(), "nothing was left in flight");

    let entries = LedgerStore::open(db.to_str().unwrap()).unwrap().decisions().unwrap();
    let decided: Vec<_> = entries.iter().map(|e| (e.decision, e.reason.as_str())).collect();
    assert_eq!(decided, [(Decision::Allow, "ok"), (Decision::Deny, "undeclared_tool"), (Decision::Deny, "unreadable")]);
}

#[test]
fn without_a_gate_messages_pass_through_verbatim() {
    let i = Interceptor::new(ctx(None, None)).unwrap();
    assert_eq!(
        i.on_agent_line("not json at all"),
        [Action::ToUpstream { server: DEFAULT_SERVER.into(), message: "not json at all".into() }]
    );
    assert_eq!(i.on_upstream_line(DEFAULT_SERVER, "log line"), [Action::ToAgent("log line".into())]);
}

#[test]
fn an_upstream_transport_error_answers_the_call_closed() {
    let i = Interceptor::new(ctx(Some(support_gate()), None)).unwrap();
    let actions = i.on_agent_line(&call(1, "refund"));
    let [Action::ToUpstream { message, .. }] = actions.as_slice() else { panic!("{actions:?}") };
    // The message never got an answer (connection refused, HTTP 500, …):
    // the agent is told, rather than left waiting.
    let error = agent_message(&i.on_upstream_error(DEFAULT_SERVER, message, "connection refused"));
    assert_eq!(error["id"], 1);
    assert_eq!(error["error"]["code"], cloakpipe_mcp::UPSTREAM_UNAVAILABLE);
    assert_eq!(error["error"]["data"]["reason"], "upstream_unavailable");
    assert!(!error.to_string().contains("connection refused"), "transport detail stays in the log: {error}");
    // A notification takes no answer.
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string();
    assert!(i.on_upstream_error(DEFAULT_SERVER, &note, "connection refused").is_empty());
}

#[test]
fn an_http_upstream_carries_its_url_and_headers() {
    let up = Upstream::http(DEFAULT_SERVER, "https://tools.example/mcp", vec![("X-Api-Key".into(), "k".into())]);
    assert_eq!(
        up.transport,
        UpstreamTransport::Http { url: "https://tools.example/mcp".into(), headers: vec![("X-Api-Key".into(), "k".into())] }
    );
}
