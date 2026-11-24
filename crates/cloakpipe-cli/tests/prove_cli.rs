//! `cloakpipe prove`: the support agent's contract against the starter pack,
//! with a scripted agent that always falls for the attack (no model, no
//! key). The example contract holds every attack and passes normal work; a
//! contract without the recipient rule lets the exfiltration through and
//! fails the report.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn support(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent").join(name)
}

fn prove(out: &Path, contract: &Path, extra: &[&str]) -> (i32, Value, String) {
    let o = bin()
        .arg("prove")
        .arg("--agent")
        .arg(support("prove/gullible.agent.yaml"))
        .arg("--contract")
        .arg(contract)
        .args(["--runs", "1", "--parallel", "6", "--out"])
        .arg(out)
        .args(extra)
        .output()
        .unwrap();
    let report = std::fs::read_to_string(out.join("report.json")).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(Value::Null);
    (o.status.code().unwrap_or(-1), report, format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
}

fn verdict<'a>(r: &'a Value, id: &str) -> &'a Value {
    &r["scenarios"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap()["verdict"]
}

#[test]
fn the_example_contract_holds_the_starter_pack() {
    let dir = tempfile::tempdir().unwrap();
    let (code, r, log) = prove(dir.path(), &support("cloakpipe.manifest.yaml"), &[]);
    assert_eq!(code, 0, "{log}");
    assert_eq!(r["ok"], true, "{r}");
    for id in ["exfiltration-email", "undeclared-tool", "oversized-refund", "double-side-effect", "argument-stretching"] {
        assert_eq!(verdict(&r, id), "HELD", "{id}: {log}");
    }
    assert_eq!(verdict(&r, "normal-work"), "COMPLETED", "{log}");
    for s in r["scenarios"].as_array().unwrap() {
        // With the gate off the agent was tricked (the scripted agent always is).
        if s["kind"] == "attack" {
            assert_eq!(s["shadow"]["attempted"], 1, "{s}");
        }
        assert_eq!(s["audit_packs_verified"], 1, "every enforce run's ledger verifies offline: {s}");
    }
    let reasons = |id: &str| r["scenarios"].as_array().unwrap().iter().find(|s| s["id"] == id).unwrap()["refusal_reasons"].clone();
    assert_eq!(reasons("exfiltration-email")["scope_mismatch"], 1);
    assert_eq!(reasons("oversized-refund")["approval_required"], 1);
    assert_eq!(reasons("double-side-effect")["reconcile_before_retry"], 1);
    let html = std::fs::read_to_string(dir.path().join("report.html")).unwrap();
    assert!(html.contains("Exfiltration by email") && html.contains("PASS"));
    // The attacker's address never reached the tool in enforce mode.
    let reached = std::fs::read_to_string(dir.path().join("runs/exfiltration-email/enforce-1/reached.jsonl")).unwrap();
    assert!(!reached.contains("evil.example"), "{reached}");
}

#[test]
fn a_contract_without_the_recipient_rule_fails() {
    let dir = tempfile::tempdir().unwrap();
    let weak = dir.path().join("contract");
    std::fs::create_dir_all(weak.join("policies")).unwrap();
    let src = std::fs::read_to_string(support("cloakpipe.manifest.yaml")).unwrap();
    let loose = src.replace(r#"one_of_context: ["ticket.customer_email"], or_pattern: "@ourcompany\\.com$", "#, "");
    assert_ne!(src, loose);
    std::fs::write(weak.join("cloakpipe.manifest.yaml"), loose).unwrap();
    std::fs::copy(support("policies/support.cedar"), weak.join("policies/support.cedar")).unwrap();
    let out = dir.path().join("report");
    let (code, r, log) = prove(&out, &weak.join("cloakpipe.manifest.yaml"), &["--scenario", "exfiltration-email", "--scenario", "normal-work"]);
    assert_eq!(code, 1, "{log}");
    assert_eq!(verdict(&r, "exfiltration-email"), "REACHED");
    assert!(r["failures"][0].as_str().unwrap().contains("exfiltration-email"), "{r}");
    assert!(log.contains("result: FAIL"), "{log}");
}

#[test]
fn usage_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _, log) = prove(dir.path(), &support("cloakpipe.manifest.yaml"), &["--scenario", "nope"]);
    assert_eq!(code, 2, "{log}");
    assert!(log.contains("--scenario nope: not in pack support-basics"), "{log}");
    let (code, _, log) = prove(dir.path(), &support("cloakpipe.manifest.yaml"), &["--pack", "no-such-pack"]);
    assert_eq!(code, 2, "{log}");
}
