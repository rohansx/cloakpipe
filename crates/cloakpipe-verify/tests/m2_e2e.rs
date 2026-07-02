//! M2 end-to-end gate: invoke the `cloakpipe-verify` binary as a
//! separate process.
//!
//! This is the strongest version of the M2 gate, because it proves
//! the verifier is genuinely standalone — not just standalone at the
//! crate level, but standalone as a *binary* a hostile third party
//! can run on a clean machine with nothing but this crate's output.
//!
//! What this gate verifies:
//! 1. The CLI exits 0 on a valid bundle.
//! 2. The CLI exits 1 on a tampered bundle (modified canonical bytes).
//! 3. The CLI exits 2 on a missing path.
//! 4. The CLI exits 1 on a bundle with the wrong magic string.
//! 5. The CLI exits 1 on a bundle with the wrong format_version.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

fn verify_bin() -> PathBuf {
    // cargo sets CARGO_BIN_EXE_<name> for integration tests of bins
    // in the same crate. This is the canonical, robust way to find
    // the test binary regardless of build profile.
    PathBuf::from(env!("CARGO_BIN_EXE_cloakpipe-verify"))
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sample.bundle.json")
}

#[test]
fn cli_chain_passes_on_valid_bundle() {
    let out = Command::new(verify_bin())
        .arg("chain")
        .arg(fixture_path())
        .output()
        .expect("run binary");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"), "stdout: {stdout}");
    assert!(stdout.contains("10 record"), "stdout: {stdout}");
}

#[test]
fn cli_all_passes_on_valid_bundle() {
    let out = Command::new(verify_bin())
        .arg("all")
        .arg(fixture_path())
        .output()
        .expect("run binary");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("OK"));
}

#[test]
fn cli_chain_fails_on_tampered_bundle() {
    // Read, flip a byte in the canonical bytes of record 0, write to a
    // temp file.
    let raw = std::fs::read_to_string(fixture_path()).unwrap();
    let mut bundle: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let recs = bundle
        .get_mut("records")
        .and_then(|r| r.as_array_mut())
        .expect("records");
    let first = &mut recs[0];
    let cb = first
        .get("canonical_bytes")
        .and_then(|v| v.as_str())
        .expect("canonical_bytes")
        .to_string();
    let mut s = cb;
    let c = s.remove(0);
    s.insert(0, if c == 'A' { 'B' } else { 'A' });
    first["canonical_bytes"] = serde_json::Value::String(s);

    let dir = tempfile::tempdir().unwrap();
    let tampered = dir.path().join("tampered.json");
    let mut f = std::fs::File::create(&tampered).unwrap();
    f.write_all(serde_json::to_string_pretty(&bundle).unwrap().as_bytes())
        .unwrap();
    drop(f);

    let out = Command::new(verify_bin())
        .arg("chain")
        .arg(&tampered)
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(1), "expected failure exit code");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL"), "stdout: {stdout}");
    assert!(
        stdout.contains("hash mismatch") || stdout.contains("tamper"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_chain_fails_on_missing_path() {
    let out = Command::new(verify_bin())
        .arg("chain")
        .arg("/nonexistent/path.json")
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn cli_chain_fails_on_wrong_magic() {
    let raw = std::fs::read_to_string(fixture_path()).unwrap();
    let mut bundle: serde_json::Value = serde_json::from_str(&raw).unwrap();
    bundle["format"] = serde_json::Value::String("evil.bundle".into());
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.json");
    std::fs::write(&p, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let out = Command::new(verify_bin())
        .arg("all")
        .arg(&p)
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("format mismatch"),
        "stdout: {stdout}"
    );
}

#[test]
fn cli_chain_fails_on_wrong_version() {
    let raw = std::fs::read_to_string(fixture_path()).unwrap();
    let mut bundle: serde_json::Value = serde_json::from_str(&raw).unwrap();
    bundle["format_version"] = serde_json::Value::Number(999.into());
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.json");
    std::fs::write(&p, serde_json::to_string_pretty(&bundle).unwrap()).unwrap();

    let out = Command::new(verify_bin())
        .arg("all")
        .arg(&p)
        .output()
        .expect("run binary");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not supported"),
        "stdout: {stdout}"
    );
}