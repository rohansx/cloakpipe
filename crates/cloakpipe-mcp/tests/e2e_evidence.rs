//! End-to-end gate: interception → evidence ledger → export → offline verify.
//!
//! Drives the real MCP interceptor, with the opt-in PII transform
//! (`mcp-proxy --transform pii`), against a real spawned upstream "tool"
//! (a shell script) and proves, in one flow:
//!
//! 1. Raw PII in `tools/call` arguments never reaches the upstream tool.
//! 2. The tool's echoed pseudonyms are restored before the agent sees them.
//! 3. Each hop is appended to the evidence ledger.
//! 4. Every hop is bound to the Agent Release the interceptor runs as.
//! 5. The ledger exports to a signed bundle that the standalone verifier
//!    accepts, and the bundle itself contains no raw PII.

use cloakpipe_core::{config::DetectionConfig, detector::Detector, vault::Vault};
use cloakpipe_ledger::{export, Ed25519Signer, LedgerStore};
use cloakpipe_mcp::{run_proxy_io, stable_ids, PiiTransform, ProxyContext};
use std::io::{Cursor, Write};
use std::sync::{Arc, Mutex};

const EMAIL_A: &str = "alice@acme.com";
const EMAIL_B: &str = "bob@globex.com";
/// The Agent Release the interceptor is running as.
const RELEASE: [u8; 32] = [0xae; 32];

/// Collects everything the interceptor writes back to the agent.
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

/// A fake MCP tool: records every line it receives to `received`, and answers a
/// `tools/call` by echoing its (masked) arguments back as the result content.
/// `params` serializes as `{"name":"...","arguments":...}` (the agent's key
/// order, kept when serde_json's `preserve_order` is on, as the Cedar engine
/// turns it on) or as `{"arguments":...,"name":"..."}` (sorted keys).
fn write_fake_upstream(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let received = dir.join("upstream_received.jsonl");
    let script = dir.join("fake_tool.sh");
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
while IFS= read -r line; do
  printf '%s\n' "$line" >> '{received}'
  printf '%s\n' "$line" | sed \
    -e 's/^.*"params":{{"name":"[^"]*","arguments":\(.*\)}}}}$/{{"jsonrpc":"2.0","id":1,"result":{{"content":\1}}}}/' \
    -e 's/^.*"params":{{"arguments":\(.*\),"name":"[^"]*"}}}}$/{{"jsonrpc":"2.0","id":1,"result":{{"content":\1}}}}/'
done
"#,
            received = received.display()
        ),
    )
    .unwrap();
    (script, received)
}

#[test]
fn pii_never_reaches_tool_and_evidence_verifies_offline() {
    let dir = tempfile::tempdir().unwrap();
    let (script, received) = write_fake_upstream(dir.path());
    let ledger_db = dir.path().join("ledger.db");

    let config: DetectionConfig = serde_json::from_str("{}").unwrap();
    let ctx = ProxyContext {
        // The PII transform is opt-in (`mcp-proxy --transform pii`).
        pii: Some(PiiTransform { detector: Detector::from_config(&config).unwrap(), vault: Vault::ephemeral() }),
        ledger_db: Some(ledger_db.to_string_lossy().into_owned()),
        release: Some(RELEASE),
        gate: None,
        decisions: None,
        events: Vec::new(),
        capture: None,
    };

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "send_email",
            "arguments": { "to": format!("email {EMAIL_A} about the invoice"), "cc": [EMAIL_B] }
        }
    });
    let agent_in = Cursor::new(format!("{request}\n").into_bytes());
    let agent_out = Capture::default();

    run_proxy_io(
        vec!["sh".into(), script.to_string_lossy().into_owned()],
        ctx,
        agent_in,
        agent_out.clone(),
    )
    .expect("interceptor runs");

    // 1. The tool saw the call, but only pseudonyms.
    let upstream_saw = std::fs::read_to_string(&received).expect("upstream received the call");
    assert!(upstream_saw.contains("tools/call"), "upstream got: {upstream_saw}");
    assert!(!upstream_saw.contains(EMAIL_A), "raw PII reached the tool: {upstream_saw}");
    assert!(!upstream_saw.contains(EMAIL_B), "raw PII reached the tool: {upstream_saw}");

    // 2. The agent got the originals back.
    let agent_saw = String::from_utf8(agent_out.0.lock().unwrap().clone()).unwrap();
    assert!(agent_saw.contains(EMAIL_A), "agent should see restored values: {agent_saw}");
    assert!(agent_saw.contains(EMAIL_B), "agent should see restored values: {agent_saw}");

    // 3. Both hops were recorded.
    let (tenant, _) = stable_ids();
    let store = LedgerStore::open(ledger_db.to_str().unwrap()).unwrap();
    let records = store.records_for_tenant(&tenant).unwrap();
    assert_eq!(records.len(), 2, "tool call + tool result");
    for r in &records {
        assert_eq!(r.record.release_hash(), Some(RELEASE), "every hop is bound to the release");
    }

    // 4. Export, then verify with the standalone verifier from the file alone.
    let bundle = export::export_bundle(&store, &tenant, &Ed25519Signer::generate()).unwrap();
    let bundle_path = dir.path().join("evidence.bundle.json");
    export::write_bundle(&bundle_path, &bundle).unwrap();

    let bundle_json = std::fs::read_to_string(&bundle_path).unwrap();
    assert!(!bundle_json.contains(EMAIL_A), "evidence bundle must not contain raw PII");
    assert!(!bundle_json.contains(EMAIL_B), "evidence bundle must not contain raw PII");

    let parsed: cloakpipe_verify::bundle::Bundle = serde_json::from_str(&bundle_json).unwrap();
    let summary = cloakpipe_verify::verify::verify_all(&parsed).expect("bundle verifies offline");
    assert_eq!(summary.records, 2);
    assert!(
        parsed.records.iter().all(|r| r.canonical_bytes.contains(&format!("release_hash=hash:{}", "ae".repeat(32)))),
        "the release binding is inside the signed, hash-chained bytes"
    );

    // Tampering with any recorded byte must break verification.
    let mut tampered = parsed.clone();
    tampered.records[0].canonical_bytes = tampered.records[0].canonical_bytes.replacen("mcp", "mcx", 1);
    assert!(cloakpipe_verify::verify::verify_all(&tampered).is_err(), "tampered bundle must fail");
}
