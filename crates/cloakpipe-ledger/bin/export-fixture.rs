//! Produce a fixture bundle for the `cloakpipe-verify` gate tests.
//!
//! Usage:
//!   cargo run -p cloakpipe-ledger --bin ledger-export-example -- <out_path>
//!
//! Writes a self-describing bundle containing 10 records across one
//! tenant, signed with a fresh Ed25519 key (the pubkey is included in
//! the bundle so the verifier can check signatures).

use cloakpipe_ledger::export::{export_bundle, write_bundle};
use cloakpipe_ledger::record::{Action, ActionKind, Detection, Detector, Hop, RecordBuilder};
use cloakpipe_ledger::sign::Ed25519Signer;
use cloakpipe_ledger::store::LedgerStore;
use std::env;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let out_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "crates/cloakpipe-verify/tests/fixtures/sample.bundle.json".to_string());

    // Write a ledger to a temp file, append 10 records, export.
    let tmp = tempfile::tempdir()?;
    let db_path = tmp.path().join("ledger.sqlite");
    let mut store = LedgerStore::open(db_path.to_str().unwrap())?;
    let tenant = uuid::Uuid::new_v4();
    let signer = Ed25519Signer::generate();

    for i in 0..10u64 {
        let mut r = RecordBuilder::new()
            .seq(i)
            .tenant(tenant)
            .hop(if i % 2 == 0 { Hop::LlmPrompt } else { Hop::LlmResponse })
            .detection(Detection {
                entity_type: "PAN".into(),
                count: 1,
                detector: Detector::Regex,
            })
            .action(Action {
                entity_type: "PAN".into(),
                kind: ActionKind::Pseudonymize,
                token_ref: Some(format!("tok_{i}")),
            })
            .build()?;
        store.append(&tenant, &mut r)?;
    }

    let bundle = export_bundle(&store, &tenant, &signer)?;
    let path = PathBuf::from(&out_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_bundle(&path, &bundle)?;
    println!("wrote bundle to {}", path.display());
    Ok(())
}