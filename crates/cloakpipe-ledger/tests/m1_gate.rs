//! M1 gate test — the explicit, named exit gate for milestone M1.
//!
//! Per the v2 PLAN: "append 10k records; chain verifies in-process;
//! fuzz test rejects PII in every field."
//!
//! If this file ever stops compiling or any test fails, M1 is not done.

#![cfg(test)]

use cloakpipe_ledger::{
    chain, Action, ActionKind, Detection, Detector, Hop, LedgerStore, MetadataValue,
    RecordBuilder,
};
use proptest::prelude::*;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn gate_append_10k_records_and_verify_chain() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("gate.sqlite");
    let mut store = LedgerStore::open(path.to_str().unwrap()).unwrap();
    let tenant = Uuid::new_v4();

    for i in 0..10_000u64 {
        let mut r = RecordBuilder::new()
            .seq(i)
            .tenant(tenant)
            .hop(if i % 2 == 0 { Hop::LlmPrompt } else { Hop::LlmResponse })
            .detection(Detection {
                entity_type: "PAN".into(),
                count: (i % 4) as u32,
                detector: Detector::Regex,
            })
            .action(Action {
                entity_type: "PAN".into(),
                kind: ActionKind::Pseudonymize,
                token_ref: Some(format!("tok_{i}")),
            })
            .build()
            .unwrap();
        store.append(&tenant, &mut r).unwrap();
    }

    let stored = store.records_for_tenant(&tenant).unwrap();
    assert_eq!(stored.len(), 10_000);
    let records: Vec<_> = stored.into_iter().map(|s| s.record).collect();
    chain::verify_chain(&records).expect("10k-record chain must verify");
}

// Fuzz: feed the builder 1000 random strings as metadata, none should
// produce a record that *contains* the seed verbatim if the seed looks
// PII-shaped. We can't directly observe "rejected" because proptest
// strategies also produce clean inputs — instead, we assert that for
// every seed that *does* contain a PII marker, the build rejects.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn gate_fuzz_rejects_pii_in_metadata(s in "[ -~]{0,80}") {
        let has_ws = s.chars().any(|c| c.is_whitespace());
        let lowered = s.to_ascii_lowercase();
        let has_marker = [
            "@", "aadhaar", "pan", "ifsc", "upi://", "gstin",
            "ssn", "phone", "email", "name=",
        ].iter().any(|m| lowered.contains(m));
        let too_long = s.len() > 128;

        let res = RecordBuilder::new()
            .metadata("k", MetadataValue::OpaqueId(s.clone()))
            .build();

        if has_ws || has_marker || too_long {
            prop_assert!(
                res.is_err(),
                "validator let through PII-shaped metadata: {:?}",
                s
            );
        }
    }
}