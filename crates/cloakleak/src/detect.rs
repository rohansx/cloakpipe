//! Entity taxonomy + leak detection.
//!
//! An *entity* is a category of PII (e.g. `PAN`, `Aadhaar`). A *leak*
//! is one instance of an entity that survived masking.
//!
//! Detection is intentionally regex-based and conservative:
//! - We score **leaks**, not F1. A single surviving instance is a
//!   failure regardless of how many were caught.
//! - Regexes are run on the *redacted output*, not the input — i.e.
//!   we ask "did the SUT leave this identifier visible?"

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityClass {
    /// India Permanent Account Number — 5 letters, 4 digits, 1 letter
    /// (e.g. ABCDE1234F). Looser regex: any `\b[A-Z]{5}\d{4}[A-Z]\b`.
    Pan,
    /// India Aadhaar — 12 digits, often space-grouped as
    /// `XXXX XXXX XXXX`. Looser regex: any 12-digit run.
    Aadhaar,
    /// Indian phone — 10 digits, optionally prefixed `+91` or `0`.
    Phone,
    /// UPI handle — `name@bank`.
    Upi,
    /// GSTIN — 15-char alphanumeric.
    Gstin,
    /// IFSC — 11-char bank branch code.
    Ifsc,
    /// Email
    Email,
    /// US SSN — `NNN-NN-NNNN`.
    Ssn,
    /// Credit-card-shaped 16-digit run (Luhn not enforced here — that's
    /// the detector's job, not the leak-scoring job).
    Card,
    /// Voter ID — 3 letters + 7 digits.
    VoterId,
}

impl EntityClass {
    /// Canonical slug used in the scoreboard and corpus filenames.
    pub fn slug(&self) -> &'static str {
        match self {
            EntityClass::Pan => "pan",
            EntityClass::Aadhaar => "aadhaar",
            EntityClass::Phone => "phone",
            EntityClass::Upi => "upi",
            EntityClass::Gstin => "gstin",
            EntityClass::Ifsc => "ifsc",
            EntityClass::Email => "email",
            EntityClass::Ssn => "ssn",
            EntityClass::Card => "card",
            EntityClass::VoterId => "voter_id",
        }
    }

    /// Regex used to find surviving instances in the redacted output.
    /// Deliberately loose — false positives in *detection* only inflate
    /// the leak count, which is a safe direction (we want to fail
    /// loud).
    pub fn regex(&self) -> Regex {
        match self {
            EntityClass::Pan => Regex::new(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b").unwrap(),
            EntityClass::Aadhaar => Regex::new(r"\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b").unwrap(),
            EntityClass::Phone => Regex::new(r"(?:\+?91[-\s]?)?[6-9][0-9]{9}\b").unwrap(),
            EntityClass::Upi => Regex::new(r"\b[a-zA-Z0-9._-]{3,}@[a-zA-Z][a-zA-Z0-9]+\b").unwrap(),
            EntityClass::Gstin => Regex::new(r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][0-9A-Z][Z][0-9A-Z]\b").unwrap(),
            EntityClass::Ifsc => Regex::new(r"\b[A-Z]{4}0[A-Z0-9]{6}\b").unwrap(),
            EntityClass::Email => Regex::new(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b").unwrap(),
            EntityClass::Ssn => Regex::new(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b").unwrap(),
            EntityClass::Card => Regex::new(r"\b[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b").unwrap(),
            EntityClass::VoterId => Regex::new(r"\b[A-Z]{3}[0-9]{7}\b").unwrap(),
        }
    }

    pub fn all() -> &'static [EntityClass] {
        &[
            EntityClass::Pan,
            EntityClass::Aadhaar,
            EntityClass::Phone,
            EntityClass::Upi,
            EntityClass::Gstin,
            EntityClass::Ifsc,
            EntityClass::Email,
            EntityClass::Ssn,
            EntityClass::Card,
            EntityClass::VoterId,
        ]
    }
}

/// A single leaked instance: where it was found, what entity class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Leak {
    pub entity: EntityClass,
    pub matched: String,
    pub start: usize,
    pub end: usize,
}

/// Scan `text` for surviving instances of every entity class.
/// Returns every match, not just the first — a single sample can leak
/// the same class multiple times.
pub fn find_leaks(text: &str) -> Vec<Leak> {
    let mut out = Vec::new();
    for class in EntityClass::all() {
        let re = class.regex();
        for m in re.find_iter(text) {
            out.push(Leak {
                entity: *class,
                matched: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pan() {
        let leaks = find_leaks("ABCDE1234F");
        assert!(leaks.iter().any(|l| l.entity == EntityClass::Pan));
    }

    #[test]
    fn detects_aadhaar_with_spaces() {
        let leaks = find_leaks("Aadhaar 1234 1234 1234 here");
        assert!(leaks.iter().any(|l| l.entity == EntityClass::Aadhaar));
    }

    #[test]
    fn detects_phone_with_country_code() {
        let leaks = find_leaks("call +91 9876543210");
        assert!(leaks.iter().any(|l| l.entity == EntityClass::Phone));
    }

    #[test]
    fn detects_email() {
        let leaks = find_leaks("mail alice@example.com please");
        assert!(leaks.iter().any(|l| l.entity == EntityClass::Email));
    }

    #[test]
    fn detects_upi() {
        // UPI regex is broader than email (no TLD); accept a 2-part handle.
        let leaks = find_leaks("pay alice@oksbi");
        assert!(leaks.iter().any(|l| l.entity == EntityClass::Upi));
    }

    #[test]
    fn clean_text_has_no_leaks() {
        let clean = "Hello world, please generate a haiku about sunrise.";
        let leaks = find_leaks(clean);
        assert!(leaks.is_empty(), "got: {leaks:?}");
    }

    #[test]
    fn slug_table_is_stable() {
        // Wire format. Renaming any slug is a breaking change for the
        // scoreboard JSON.
        assert_eq!(EntityClass::Pan.slug(), "pan");
        assert_eq!(EntityClass::Aadhaar.slug(), "aadhaar");
        assert_eq!(EntityClass::Phone.slug(), "phone");
        assert_eq!(EntityClass::Email.slug(), "email");
    }
}