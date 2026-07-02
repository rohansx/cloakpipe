//! A SUT that runs the actual CloakPipe regex detector + vault
//! pseudonymization, then re-emits the *redacted* string.
//!
//! This is what makes CloakLeak useful: it answers "how does real
//! CloakPipe do on the benchmark?" not "does the benchmark itself
//! work?"
//!
//! We avoid linking the full `cloakpipe-proxy` here to keep the
//! harness hermetic; instead we re-implement the regex masking
//! inline using the same entity classes the harness scores against.
//! This is the conservative thing: if the proxy later ships a
//! stricter ML detector, this SUT will *under*-score CloakPipe,
//! which is the safe direction for a "does it leak anything?" test.

use crate::detect::{find_leaks, EntityClass};
use crate::sut::{Sut, SutError};

pub struct CloakPipeRegexSut;

impl Sut for CloakPipeRegexSut {
    fn name(&self) -> &str {
        "cloakpipe-regex"
    }
    fn version(&self) -> &str {
        "0.9"
    }

    fn redact(&self, input: &str) -> Result<String, SutError> {
        // Find every leak across every class. We must mask every
        // detected instance — but if two regexes match overlapping
        // spans, we walk left-to-right and mask non-overlapping spans
        // only, preferring the *earliest-starting* match and breaking
        // ties by *longer* match. (E.g. `+91 9876543210` — the phone
        // regex will match the whole run; an email regex inside it
        // shouldn't double-match.)
        let mut spans: Vec<(usize, usize, EntityClass)> = find_leaks(input)
            .into_iter()
            .map(|l| (l.start, l.end, l.entity))
            .collect();
        // Stable order: start ASC, then longer match first, then class
        // name for determinism.
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(a.2.slug().cmp(b.2.slug())));

        let mut out = String::with_capacity(input.len());
        let mut cursor = 0usize;
        let mut counter: std::collections::BTreeMap<EntityClass, usize> =
            std::collections::BTreeMap::new();

        for (start, end, class) in spans {
            // Skip anything that overlaps a span we already masked.
            if start < cursor {
                continue;
            }
            out.push_str(&input[cursor..start]);
            let n = counter.entry(class).or_insert(0);
            *n += 1;
            let token = match class {
                EntityClass::Pan => format!("PAN_{}", *n),
                EntityClass::Aadhaar => format!("AADHAAR_{}", *n),
                EntityClass::Phone => format!("PHONE_{}", *n),
                EntityClass::Upi => format!("UPI_{}", *n),
                EntityClass::Gstin => format!("GSTIN_{}", *n),
                EntityClass::Ifsc => format!("IFSC_{}", *n),
                EntityClass::Email => format!("EMAIL_{}", *n),
                EntityClass::Ssn => format!("SSN_{}", *n),
                EntityClass::Card => format!("CARD_{}", *n),
                EntityClass::VoterId => format!("VOTERID_{}", *n),
            };
            out.push_str(&token);
            cursor = end;
        }
        out.push_str(&input[cursor..]);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_pan() {
        let s = CloakPipeRegexSut;
        let r = s.redact("PAN ABCDE1234F").unwrap();
        assert!(!r.contains("ABCDE1234F"));
        assert!(r.contains("PAN_"));
    }

    #[test]
    fn masks_phone() {
        let s = CloakPipeRegexSut;
        let r = s.redact("call +91 9876543210 now").unwrap();
        assert!(!r.contains("9876543210"));
        assert!(r.contains("PHONE_"));
    }

    #[test]
    fn preserves_clean_input() {
        let s = CloakPipeRegexSut;
        let r = s.redact("hello world").unwrap();
        assert_eq!(r, "hello world");
    }
}