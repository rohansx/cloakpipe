//! Integration tests for the `cloakpipe scan` CLI command.

use std::fs;
use std::process::Command;

#[test]
fn test_scan_detect_only() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("test.txt");
    fs::write(&input, "Contact Rajesh at rajesh@example.com or +91 98765 43210").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
        .args(["scan", input.to_str().unwrap(), "--detect-only"])
        .output()
        .expect("failed to run cloakpipe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "scan should succeed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("Total entities:"), "Should show summary");
}

#[test]
fn test_scan_mask_output() {
    let dir = tempfile::tempdir().unwrap();
    let input_dir = dir.path().join("docs");
    let output_dir = dir.path().join("docs-masked");
    fs::create_dir(&input_dir).unwrap();
    fs::write(
        input_dir.join("file.txt"),
        "Patient Rajesh Singh, email rajesh@hospital.com, Aadhaar 2345 6789 0123",
    ).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
        .args([
            "scan",
            input_dir.to_str().unwrap(),
            "-o", output_dir.to_str().unwrap(),
        ])
        .output()
        .expect("failed to run cloakpipe");

    assert!(output.status.success(), "scan should succeed: {}", String::from_utf8_lossy(&output.stderr));

    // Verify output file exists and doesn't contain original PII
    let masked = fs::read_to_string(output_dir.join("file.txt")).unwrap();
    assert!(!masked.contains("rajesh@hospital.com"), "Email should be masked");

    // Verify vault mappings file exists
    assert!(output_dir.join("vault-mappings.json").exists(), "vault mappings should be exported");
}

#[test]
fn test_scan_no_files() {
    let dir = tempfile::tempdir().unwrap();
    let input_dir = dir.path().join("empty");
    fs::create_dir(&input_dir).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_cloakpipe"))
        .args(["scan", input_dir.to_str().unwrap(), "--detect-only"])
        .output()
        .expect("failed to run cloakpipe");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("No scannable files"));
}
