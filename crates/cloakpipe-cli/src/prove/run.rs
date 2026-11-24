//! One `prove` run: set up its directory, then measure what happened.
//!
//! The agent talks to a chain of three processes, all on stdio:
//!
//! ```text
//! agent -> mcp-proxy --capture (attempts)  -> mcp-proxy --manifest (the gate, shadow or enforce)
//!       -> prove-stub (what reached the tools)
//! ```
//!
//! so every run has three independent records: what the agent *attempted*
//! (the capture, raw arguments, before the gate), what the gate *decided*
//! (its events log and signed decision ledger) and what *reached* a tool
//! (the stub's log).

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::pack::{Kind, Matcher, Pack, Scenario};
use super::sandbox::{write, Finished, Job};
use super::stub::StubConfig;

/// Shadow (calls pass, decisions recorded) or enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Shadow,
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    }
}

/// What a run needs that is the same for every run.
pub struct Setup<'a> {
    pub exe: &'a Path,
    /// The contract (a v1 manifest) and its policy, if any, as declared.
    pub contract: &'a Path,
    pub policy: Option<&'a str>,
    pub agent: &'a super::Agent,
    pub pack: &'a Pack,
    /// Host-only files (approver private keys), never in a run directory.
    pub private: &'a Path,
}

/// Prepare the run directory for `scenario` in `mode` and return its job.
pub fn prepare(s: &Setup, scenario: &Scenario, mode: Mode, dir: &Path) -> Result<Job, String> {
    let p = |name: &str| dir.join(name);
    std::fs::create_dir_all(p("home")).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The contract, with its policy at the same relative path.
    let contract_name = s.contract.file_name().ok_or("--contract: not a file")?;
    let contract = p("contract").join(contract_name);
    write(&contract, &std::fs::read_to_string(s.contract).map_err(|e| format!("{}: {e}", s.contract.display()))?)?;
    if let Some(policy) = s.policy {
        let from = s.contract.parent().unwrap_or(Path::new(".")).join(policy);
        write(&p("contract").join(policy), &std::fs::read_to_string(&from).map_err(|e| format!("{}: {e}", from.display()))?)?;
    }
    write(&p("context.json"), &scenario.task.to_string())?;
    write(&p("task.json"), &json!({ "prompt": scenario.prompt, "context": scenario.task }).to_string())?;
    let stub = StubConfig { tools: s.pack.tools.clone(), ticket: scenario.ticket.clone(), behaviour: scenario.stub.clone() };
    write(&p("stub.json"), &serde_json::to_string(&stub).map_err(|e| e.to_string())?)?;
    write(&p("reached.jsonl"), "")?;

    let exe = s.exe.to_string_lossy().into_owned();
    let path = |name: &str| p(name).to_string_lossy().into_owned();
    let stub_cmd = shell_words::join([exe.as_str(), "prove-stub", "--config", &path("stub.json"), "--log", &path("reached.jsonl")]);
    let mut gate = vec![
        exe.clone(), "mcp-proxy".into(), "--upstream".into(), stub_cmd,
        "--manifest".into(), contract.to_string_lossy().into_owned(), "--mode".into(), mode.as_str().into(),
        "--task-context".into(), path("context.json"), "--operations-db".into(), path("ops.db"),
        "--state-db".into(), path("state.db"), "--events-log".into(), path("events.jsonl"),
    ];
    if let Some(approved) = &scenario.approved {
        approve(s.exe, &contract, approved, dir, s.private)?;
        gate.extend(["--approvals".into(), path("approvals"), "--approver-key".into(), path("approver.pub.json")]);
    }
    // The outer proxy records every attempt before the gate sees it.
    let chain = vec![
        "env".to_string(), format!("CLOAKPIPE_HOME={}", path("home")),
        exe, "mcp-proxy".into(), "--upstream".into(), shell_words::join(&gate), "--capture".into(), path("attempts"),
    ];
    let mcp = json!({ "mcpServers": { "tools": { "command": chain[0], "args": chain[1..] } } });
    write(&p("mcp.json"), &serde_json::to_string_pretty(&mcp).map_err(|e| e.to_string())?)?;

    let mut env: Vec<(String, String)> = s.agent.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    for var in &s.agent.pass_env {
        if let Ok(v) = std::env::var(var) {
            env.push((var.clone(), v));
        }
    }
    env.extend([
        ("CLOAKPIPE_PROVE_GATE".into(), shell_words::join(&chain)),
        ("CLOAKPIPE_PROVE_MCP_CONFIG".into(), path("mcp.json")),
        ("CLOAKPIPE_PROVE_TASK".into(), path("task.json")),
        ("CLOAKPIPE_PROVE_PROMPT".into(), scenario.prompt.clone()),
        ("CLOAKPIPE_PROVE_USAGE".into(), path("usage.json")),
        ("CLOAKPIPE_PROVE_SCENARIO".into(), scenario.id.clone()),
    ]);
    Ok(Job { run_dir: dir.to_path_buf(), agent_dir: s.agent.dir.clone(), command: s.agent.command.clone(), env, timeout: s.agent.timeout })
}

/// Sign an approval receipt for the scenario's approved call, before the
/// run. The approver's private key stays in `private`, outside the run
/// directory (and so outside any sandbox): the agent gets only the public part.
fn approve(exe: &Path, contract: &Path, approved: &super::pack::ApprovedCall, dir: &Path, private: &Path) -> Result<(), String> {
    write(&dir.join("approved-args.json"), &approved.args.to_string())?;
    let key = private.join(format!("{:016x}.key", rand::random::<u64>()));
    let ok = |c: &mut Command, what: &str| -> Result<Vec<u8>, String> {
        let out = c.output().map_err(|e| format!("{what}: {e}"))?;
        out.status.success().then_some(out.stdout).ok_or_else(|| format!("{what}: {}", String::from_utf8_lossy(&out.stderr)))
    };
    let public = ok(Command::new(exe).args(["release", "keygen", "--out"]).arg(&key), "approver keygen")?;
    write(&dir.join("approver.pub.json"), &String::from_utf8_lossy(&public))?;
    ok(
        Command::new(exe)
            .arg("approve")
            .arg("--manifest")
            .arg(contract)
            .args(["--tool", &approved.tool, "--args"])
            .arg(dir.join("approved-args.json"))
            .arg("--task-context")
            .arg(dir.join("context.json"))
            .arg("--key")
            .arg(&key)
            // Within any approval ttl the contract is likely to set.
            .arg("--expires")
            .arg("5m")
            .arg("--out")
            .arg(dir.join("approvals")),
        "approve",
    )
    .map(|_| ())
}

/// What one run showed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Outcome {
    pub scenario: String,
    pub mode: Mode,
    pub run: usize,
    pub dir: PathBuf,
    /// The agent finished (exit 0, in time).
    pub ok: bool,
    pub finished: Option<Finished>,
    pub error: Option<String>,
    /// Attack: the agent made the bad call / it reached the tool.
    pub attempted: bool,
    pub reached: bool,
    /// Gate refusals of the scenario's tool (attack) or of any call (control), by reason.
    pub refusals: BTreeMap<String, usize>,
    /// Control: every must_reach call reached its tool.
    pub completed: bool,
    pub usage: Option<Value>,
    /// Enforce: the run's decision ledger exported and verified offline.
    pub audit_pack: Option<PathBuf>,
    pub audit_verified: Option<bool>,
}

/// Read the run's records and judge it.
pub fn measure(scenario: &Scenario, mode: Mode, run: usize, dir: &Path, finished: Result<Finished, String>, exe: &Path) -> Outcome {
    let attempts = calls(&std::fs::read_dir(dir.join("attempts")).into_iter().flatten().flatten().map(|e| e.path()).collect::<Vec<_>>(), true);
    let reached = calls(&[dir.join("reached.jsonl")], false);
    let events = jsonl(&dir.join("events.jsonl"));
    let (attempts, reached) = (borrowed(&attempts), borrowed(&reached));
    let met = |m: &Matcher, c: &[(&str, Option<&Value>)]| m.met_by(c.iter().copied());
    let mut o = Outcome {
        scenario: scenario.id.clone(),
        mode,
        run,
        dir: dir.to_path_buf(),
        ok: matches!(&finished, Ok(f) if f.exit == Some(0) && !f.timed_out),
        error: finished.as_ref().err().cloned(),
        finished: finished.ok(),
        attempted: false,
        reached: false,
        refusals: BTreeMap::new(),
        completed: false,
        usage: std::fs::read_to_string(dir.join("usage.json")).ok().and_then(|s| serde_json::from_str(&s).ok()),
        audit_pack: None,
        audit_verified: None,
    };
    let bad_tool = scenario.bad_call.as_ref().map(|m| m.tool.as_str());
    for e in &events {
        let kind = e.get("kind").and_then(Value::as_str).unwrap_or("");
        let refused = matches!(kind, "decision.deny" | "approval.requested" | "approval.mismatch" | "shadow.finding");
        let tool = e.get("tool").and_then(Value::as_str);
        if refused && (bad_tool.is_none() || tool == bad_tool) {
            let reason = e.get("reason").and_then(Value::as_str).unwrap_or("?").to_string();
            *o.refusals.entry(reason).or_default() += 1;
        }
    }
    match scenario.kind {
        Kind::Attack => {
            let bad = scenario.bad_call.as_ref().expect("checked at load");
            o.attempted = met(bad, &attempts);
            o.reached = met(bad, &reached);
        }
        Kind::Control => o.completed = scenario.must_reach.iter().all(|m| met(m, &reached)),
    }
    if mode == Mode::Enforce {
        let pack = dir.join("audit-pack.tar");
        let home = dir.join("home");
        let exported = Command::new(exe).args(["ledger", "export", "--out"]).arg(&pack).env("CLOAKPIPE_HOME", &home).output();
        if exported.is_ok_and(|o| o.status.success()) {
            let verified = Command::new(exe).arg("verify").arg(&pack).env("CLOAKPIPE_HOME", &home).output();
            o.audit_verified = Some(verified.is_ok_and(|o| o.status.success()));
            o.audit_pack = Some(pack);
        }
    }
    o
}

/// `(tool, args)` of every call in capture files (`capture`) or a stub log.
fn calls(files: &[PathBuf], capture: bool) -> Vec<(String, Option<Value>)> {
    let mut out = Vec::new();
    for f in files {
        for rec in jsonl(f) {
            if capture && rec.get("kind").and_then(Value::as_str) != Some("call") {
                continue;
            }
            if let Some(tool) = rec.get("tool").and_then(Value::as_str) {
                out.push((tool.to_string(), rec.get("args").filter(|a| !a.is_null()).cloned()));
            }
        }
    }
    out
}

fn borrowed(c: &[(String, Option<Value>)]) -> Vec<(&str, Option<&Value>)> {
    c.iter().map(|(t, a)| (t.as_str(), a.as_ref())).collect()
}

fn jsonl(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path).unwrap_or_default().lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}
