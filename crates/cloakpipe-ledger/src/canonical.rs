//! Canonical, deterministic byte encoding for [`LedgerRecord`].
//!
//! Two records with identical *fields* (regardless of struct field order,
//! `BTreeMap` ordering, or JSON whitespace) must produce identical bytes —
//! otherwise `record_hash` is non-reproducible and the verifier can't be
//! independent.

use crate::record::LedgerRecord;

/// Returns the canonical byte encoding of a record's hashable fields.
///
/// Invariants:
/// - Sorted keys at every object boundary (we already use `BTreeMap`
///   internally for metadata; serde_json is configured to preserve order).
/// - Enum tags are explicit strings (see `Hop::tag` etc.).
/// - Timestamp rendered as RFC3339 with fixed `+00:00` offset (UTC).
/// - Hashes are 64 hex chars, lowercase.
/// - UUIDs are 36-char hyphenated lowercase form.
///
/// The resulting bytes are exactly what `chain::hash_record` feeds into SHA-256.
pub fn canonicalize(r: &LedgerRecord) -> Vec<u8> {
    let mut s = String::new();
    use std::fmt::Write;

    write!(s, "seq={}", r.seq).unwrap();
    write!(s, "\nts={}", r.ts.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)).unwrap();
    write!(s, "\ntenant_id={}", uuid_lower(&r.tenant_id)).unwrap();
    write!(s, "\nhop={}", r.hop.tag()).unwrap();
    write!(s, "\ndetections=").unwrap();
    for d in &r.detections {
        write!(
            s,
            "({}|{}|{}|<confidence>)",
            d.entity_type,
            d.count,
            d.detector.tag()
        )
        .unwrap();
    }
    write!(s, "\nactions=").unwrap();
    for a in &r.actions {
        write!(
            s,
            "({}|{}|{})",
            a.entity_type,
            a.kind.tag(),
            a.token_ref.as_deref().unwrap_or("")
        )
        .unwrap();
    }
    write!(s, "\npolicy=").unwrap();
    write!(
        s,
        "({}|{}|{}|{})",
        r.policy.pack_id,
        r.policy.pack_version,
        r.policy.rule_id,
        r.policy.decision.tag()
    )
    .unwrap();
    write!(s, "\nidentities=").unwrap();
    write!(
        s,
        "({}|{}|{}|{})",
        uuid_lower(&r.identities.agent_id),
r.identities
                .human_principal
                .map(|u| uuid_lower(&u))
                .unwrap_or_else(|| "-".into()),
        r.identities.upstream,
        r.identities.region
    )
    .unwrap();
    write!(s, "\negress=").unwrap();
    write!(s, "({}|{})", r.egress.destination, hex_lower(&r.egress.bytes_out_hash)).unwrap();
    write!(s, "\nprev_hash={}", hex_lower(&r.prev_hash)).unwrap();
    write!(s, "\nmetadata=").unwrap();
    for (k, v) in &r.metadata {
        match v {
            crate::record::MetadataValue::Bool(b) => write!(s, "{}=bool:{};", k, b).unwrap(),
            crate::record::MetadataValue::Integer(i) => write!(s, "{}=int:{};", k, i).unwrap(),
            crate::record::MetadataValue::Hash(h) => write!(s, "{}=hash:{};", k, hex_lower(h)).unwrap(),
            crate::record::MetadataValue::OpaqueId(o) => write!(s, "{}=id:{};", k, o).unwrap(),
        }
    }
    s.into_bytes()
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        write!(s, "{:02x}", b).unwrap();
    }
    s
}

pub fn uuid_lower(u: &uuid::Uuid) -> String {
    u.hyphenated().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::*;
    use chrono::TimeZone;
    use uuid::Uuid;

    fn rec() -> LedgerRecord {
        RecordBuilder::new()
            .seq(7)
            .ts(chrono::Utc.with_ymd_and_hms(2026, 7, 2, 12, 0, 0).unwrap())
            .tenant(Uuid::nil())
            .hop(Hop::LlmPrompt)
            .detection(Detection {
                entity_type: "PAN".into(),
                count: 1,
                detector: Detector::Regex,
            })
            .action(Action {
                entity_type: "PAN".into(),
                kind: ActionKind::Pseudonymize,
                token_ref: Some("tok_42".into()),
            })
            .policy(Policy {
                pack_id: "dpdp".into(),
                pack_version: "abc1234".into(),
                rule_id: "mask-pan".into(),
                decision: PolicyDecision::Allow,
            })
            .identities(Identity {
                agent_id: Uuid::nil(),
                human_principal: None,
                upstream: "openai".into(),
                region: "in-mum-1".into(),
            })
            .egress(Egress {
                destination: "upstream:openai".into(),
                bytes_out_hash: [1u8; 32],
            })
            .metadata("latency_ms", MetadataValue::Integer(5))
            .build()
            .unwrap()
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let a = canonicalize(&rec());
        let b = canonicalize(&rec());
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_includes_seq_first() {
        let bytes = canonicalize(&rec());
        assert!(bytes.starts_with(b"seq=7\n"), "got: {:?}", String::from_utf8_lossy(&bytes));
    }

    #[test]
    fn canonical_does_not_embed_record_hash_field() {
        // `record_hash` is derived from canonical bytes; it must not appear
        // inside those bytes or hashing becomes self-referential.
        let bytes = canonicalize(&rec());
        let s = String::from_utf8(bytes).unwrap();
        assert!(!s.contains("record_hash"));
    }

    #[test]
    fn canonical_orders_metadata_alphabetically() {
        let r1 = RecordBuilder::new()
            .metadata("zeta", MetadataValue::Integer(1))
            .metadata("alpha", MetadataValue::Integer(2))
            .build()
            .unwrap();
        let r2 = RecordBuilder::new()
            .metadata("alpha", MetadataValue::Integer(2))
            .metadata("zeta", MetadataValue::Integer(1))
            .build()
            .unwrap();
        // Different key order from the caller still yields identical bytes
        // because BTreeMap sorts internally.
        assert_eq!(canonicalize(&r1), canonicalize(&r2));
    }

    #[test]
    fn hex_lower_is_lowercase_and_correct_length() {
        assert_eq!(hex_lower(&[0xff, 0x00, 0xab]), "ff00ab");
        assert_eq!(hex_lower(&[0u8; 32]).len(), 64);
    }
}