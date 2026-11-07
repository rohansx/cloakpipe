//! `cloakpipe mcp-proxy --listen ADDR --decide`: the gate decides an agent
//! framework's own tool calls (no MCP server behind it). `POST /decide` gets
//! the same decision a `tools/call` would; `POST /outcome` records what the
//! framework's tool returned; a call left without an outcome is `unknown`
//! at shutdown. The support-agent example's manifest and task context.
#![cfg(not(feature = "certification"))]

use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_cloakpipe"));
    for var in [
        "CLOAKPIPE_RELEASE",
        "CLOAKPIPE_LEDGER_DB",
        "CLOAKPIPE_SIGNING_KEY",
        "CLOAKPIPE_OPERATIONS_DB",
        "CLOAKPIPE_TASK_CONTEXT",
        "CLOAKPIPE_STATE_DB",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn example(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/support-agent")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

/// A running `--decide` listener; killed on drop.
struct Decider {
    child: Child,
    base: String,
    stderr: Arc<Mutex<String>>,
}

impl Decider {
    fn start(dir: &Path, extra: &[&str]) -> Self {
        let mut child = bin()
            .current_dir(dir)
            .args(["mcp-proxy", "--listen", "127.0.0.1:0", "--decide"])
            .args([
                "--manifest",
                &example("cloakpipe.manifest.yaml"),
                "--task-context",
                &example("task-context.json"),
            ])
            .args(["--operations-db", &dir.join("ops.db").to_string_lossy()])
            .args(extra)
            .env("CLOAKPIPE_HOME", dir.join("home"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let stderr = stderr.clone();
            let pipe = child.stderr.take().unwrap();
            std::thread::spawn(move || {
                for line in BufReader::new(pipe).lines() {
                    let Ok(line) = line else { break };
                    if let Some(rest) = line.split("decisions served on ").nth(1) {
                        let _ = tx.send(rest.split("/decide").next().unwrap().trim().to_string());
                    }
                    stderr.lock().unwrap().push_str(&format!("{line}\n"));
                }
            });
        }
        let base = match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(base) => base,
            Err(_) => {
                let _ = child.kill();
                panic!(
                    "the decider never announced its address: {}",
                    stderr.lock().unwrap()
                );
            }
        };
        Self {
            child,
            base,
            stderr,
        }
    }

    fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let resp = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap()
            .post(format!("{}{path}", self.base))
            .header("Content-Type", "application/json")
            .body(body.to_string())
            .send()
            .unwrap();
        let status = resp.status().as_u16();
        (
            status,
            serde_json::from_str(&resp.text().unwrap()).unwrap_or(Value::Null),
        )
    }

    fn decide(&self, tool: &str, arguments: Value) -> Value {
        let (status, body) = self.post("/decide", json!({"tool": tool, "arguments": arguments}));
        assert_eq!(status, 200, "{body}");
        body
    }

    fn stop(mut self) -> String {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
        std::thread::sleep(Duration::from_millis(100));
        self.stderr.lock().unwrap().clone()
    }
}

impl Drop for Decider {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn email(to: &str) -> Value {
    json!({"ticket_id": "T-1042", "to": to, "subject": "Your refund", "body": "Hi Dana, your refund for T-1042 is on its way."})
}

#[test]
fn the_framework_gets_allow_deny_approve_and_records_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let events = dir.path().join("events.jsonl");
    let d = Decider::start(dir.path(), &["--events-log", &events.to_string_lossy()]);

    // The customer on the ticket: allowed, and awaiting its outcome.
    let allowed = d.decide("send_email", email("dana@customer.example"));
    assert_eq!(allowed["decision"], "allow", "{allowed}");
    assert_eq!(allowed["mode"], "enforce");
    let call = allowed["call"].as_u64().expect("an allowed call has an id");

    // Someone else: scope_mismatch on /to, as over MCP.
    let refused = d.decide("send_email", email("dana.assistant@inbox-mail.example"));
    assert_eq!(refused["decision"], "deny", "{refused}");
    assert_eq!(refused["reason"], "scope_mismatch");
    assert_eq!(refused["data"]["path"], "/to");

    // A tool the manifest does not declare.
    let undeclared = d.decide("export_customers", json!({}));
    assert_eq!(undeclared["decision"], "deny");
    assert_eq!(undeclared["reason"], "undeclared_tool");

    // A refund over 100 needs a human: the fingerprint names the exact call.
    let held = d.decide(
        "issue_refund",
        json!({"ticket_id": "T-1042", "amount": 350}),
    );
    assert_eq!(held["decision"], "approve", "{held}");
    assert_eq!(held["reason"], "approval_required");
    assert!(held["data"]["fingerprint"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));

    // The same email again while the first is in flight: reconcile first.
    let again = d.decide("send_email", email("dana@customer.example"));
    assert_eq!(again["reason"], "reconcile_before_retry", "{again}");

    // The tool ran: its outcome settles the operation.
    let (status, recorded) = d.post("/outcome", json!({"call": call, "result": "sent"}));
    assert_eq!(status, 200, "{recorded}");
    assert_eq!(recorded["recorded"], true);
    let (status, _) = d.post("/outcome", json!({"call": call, "result": "sent"}));
    assert_eq!(status, 404, "an outcome is recorded once");

    // Done: the same email is answered from the operations store, not sent twice.
    let replayed = d.decide("send_email", email("dana@customer.example"));
    assert_eq!(replayed["decision"], "replay", "{replayed}");
    assert!(replayed["result"]["content"].is_array());

    // A call whose tool never answered fails closed: unknown until reconciled.
    let second = d.decide("send_email", json!({"ticket_id": "T-1042", "to": "dana@customer.example", "subject": "Again", "body": "Second mail."}));
    let call2 = second["call"].as_u64().unwrap();
    let (status, _) = d.post(
        "/outcome",
        json!({"call": call2, "error": "the tool timed out"}),
    );
    assert_eq!(status, 200);

    // Bad requests are refused, not decided.
    let (status, body) = d.post("/decide", json!({"arguments": {}}));
    assert_eq!(status, 400, "{body}");
    let (status, body) = d.post("/outcome", json!({"result": "x"}));
    assert_eq!(status, 400, "{body}");

    let stderr = d.stop();
    let kinds: Vec<String> = std::fs::read_to_string(&events)
        .unwrap()
        .lines()
        .map(|l| {
            serde_json::from_str::<Value>(l).unwrap()["kind"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(
        kinds.contains(&"approval.requested".to_string()),
        "{kinds:?}\n{stderr}"
    );
    assert!(
        kinds.contains(&"side_effect.unknown".to_string()),
        "{kinds:?}\n{stderr}"
    );
    assert!(
        kinds.contains(&"side_effect.replayed".to_string()),
        "{kinds:?}\n{stderr}"
    );
}

#[test]
fn health_lists_the_declared_tools_and_the_mode() {
    let dir = tempfile::tempdir().unwrap();
    let d = Decider::start(dir.path(), &["--mode", "shadow"]);
    let body: Value = reqwest::blocking::get(format!("{}/health", d.base))
        .unwrap()
        .json()
        .unwrap();
    assert_eq!(body["mode"], "shadow", "{body}");
    let tools: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap())
        .collect();
    assert!(
        tools.contains(&"send_email") && tools.contains(&"issue_refund"),
        "{tools:?}"
    );
    // Shadow mode forwards what enforce would refuse, and says so.
    let shadowed = d.decide("send_email", email("dana.assistant@inbox-mail.example"));
    assert_eq!(shadowed["decision"], "allow", "{shadowed}");
    assert_eq!(shadowed["mode"], "shadow");
}

#[test]
fn decide_needs_listen_and_no_upstream() {
    let out = bin()
        .args([
            "mcp-proxy",
            "--decide",
            "--manifest",
            &example("cloakpipe.manifest.yaml"),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--listen"), "{err}");
}
