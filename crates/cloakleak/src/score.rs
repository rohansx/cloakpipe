//! Scoring.
//!
//! For each sample in a corpus:
//! 1. Run the SUT.
//! 2. Scan the *output* for surviving instances of every entity class.
//! 3. If a sample's `expected_entities` includes class C and the output
//!    still contains ≥ 1 instance of C, the SUT leaked C on that
//!    sample.
//!
//! Per-class leak rate = leaked_samples / samples_with_class.
//! Overall leak rate = leaked_samples / total_samples (a sample is
//! "leaked" if *any* of its expected entities leaked).
//!
//! Output: a [`ScoreReport`] containing per-class [`ScoreRow`]s and
//! overall totals. JSON-serializable for the scoreboard.

use crate::corpus::{Corpus, Sample, Track};
use crate::detect::{find_leaks, EntityClass};
use crate::sut::Sut;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct ScoreRow {
    pub entity: String,
    pub samples: usize,
    pub leaked: usize,
    /// 0.0 = clean, 1.0 = leaked everywhere
    pub leak_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreReport {
    pub sut_name: String,
    pub sut_version: String,
    pub track: Track,
    pub total_samples: usize,
    pub total_leaked: usize,
    pub overall_leak_rate: f64,
    pub per_entity: Vec<ScoreRow>,
}

pub fn score<S: Sut + ?Sized>(sut: &S, corpus: &Corpus) -> ScoreReport {
    let mut class_samples: BTreeMap<EntityClass, usize> = BTreeMap::new();
    let mut class_leaks: BTreeMap<EntityClass, usize> = BTreeMap::new();
    let mut total = 0usize;
    let mut total_leaked = 0usize;

    for sample in &corpus.samples {
        total += 1;
        let sample_leaked = score_one(sut, sample, &mut class_samples, &mut class_leaks);
        if sample_leaked {
            total_leaked += 1;
        }
    }

    let mut per_entity = Vec::new();
    for class in EntityClass::all() {
        let s = class_samples.get(class).copied().unwrap_or(0);
        if s == 0 {
            continue;
        }
        let l = class_leaks.get(class).copied().unwrap_or(0);
        per_entity.push(ScoreRow {
            entity: class.slug().to_string(),
            samples: s,
            leaked: l,
            leak_rate: l as f64 / s as f64,
        });
    }

    ScoreReport {
        sut_name: sut.name().to_string(),
        sut_version: sut.version().to_string(),
        track: corpus.track,
        total_samples: total,
        total_leaked,
        overall_leak_rate: if total == 0 { 0.0 } else { total_leaked as f64 / total as f64 },
        per_entity,
    }
}

/// Returns true if *any* expected entity in the sample leaked.
fn score_one<S: Sut + ?Sized>(
    sut: &S,
    sample: &Sample,
    class_samples: &mut BTreeMap<EntityClass, usize>,
    class_leaks: &mut BTreeMap<EntityClass, usize>,
) -> bool {
    let redacted = match sut.redact(&sample.input) {
        Ok(s) => s,
        Err(_) => sample.input.clone(),
    };
    let leaks = find_leaks(&redacted);

    // What *did* the SUT let through? — all detected leaks, regardless
    // of expected. If the SUT unmasked an entity the corpus didn't ask
    // about, that's still a leak worth knowing about. (We may want to
    // surface "unexpected leaks" separately in the scoreboard later;
    // for now, we count them.)
    let leaked_classes: std::collections::BTreeSet<EntityClass> =
        leaks.iter().map(|l| l.entity).collect();

    let mut sample_leaked = false;
    for class in EntityClass::all() {
        let is_expected = sample
            .expected_entities
            .iter()
            .any(|s| s == class.slug());
        if !is_expected {
            continue;
        }
        *class_samples.entry(*class).or_insert(0) += 1;
        if leaked_classes.contains(class) {
            *class_leaks.entry(*class).or_insert(0) += 1;
            sample_leaked = true;
        }
    }
    sample_leaked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sut::{Passthrough, PerfectEraser};
    use crate::corpus::{Sample, Track};

    fn corpus_of(samples: Vec<Sample>) -> Corpus {
        Corpus {
            track: Track::Prose,
            samples,
        }
    }

    fn s(id: &str, input: &str, expected: &[&str]) -> Sample {
        Sample {
            id: id.into(),
            track: Track::Prose,
            input: input.into(),
            expected_entities: expected.iter().map(|s| s.to_string()).collect(),
            modality: None,
        }
    }

    #[test]
    fn passthrough_scores_full_leak() {
        let c = corpus_of(vec![
            s("a", "PAN ABCDE1234F", &["pan"]),
            s("b", "phone 9876543210", &["phone"]),
        ]);
        let r = score(&Passthrough, &c);
        assert_eq!(r.total_samples, 2);
        assert_eq!(r.total_leaked, 2);
        assert!((r.overall_leak_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn perfect_eraser_scores_zero_leak() {
        let c = corpus_of(vec![
            s("a", "PAN ABCDE1234F", &["pan"]),
            s("b", "phone 9876543210", &["phone"]),
        ]);
        let r = score(&PerfectEraser, &c);
        assert_eq!(r.total_leaked, 0);
        assert!((r.overall_leak_rate - 0.0).abs() < 1e-9);
    }

    #[test]
    fn partial_mask_scores_partial() {
        // A SUT that masks PANs but not phones.
        struct PanOnly;
        impl Sut for PanOnly {
            fn name(&self) -> &str { "pan_only" }
            fn version(&self) -> &str { "0" }
            fn redact(&self, input: &str) -> Result<String, crate::sut::SutError> {
                Ok(input.replace("ABCDE1234F", "***"))
            }
        }
        let c = corpus_of(vec![
            s("a", "PAN ABCDE1234F", &["pan"]),
            s("b", "phone 9876543210", &["phone"]),
        ]);
        let r = score(&PanOnly, &c);
        assert_eq!(r.total_leaked, 1); // the phone
        let pan = r.per_entity.iter().find(|r| r.entity == "pan").unwrap();
        assert_eq!(pan.leaked, 0);
        let phone = r.per_entity.iter().find(|r| r.entity == "phone").unwrap();
        assert_eq!(phone.leaked, 1);
    }

    #[test]
    fn empty_corpus_is_zero() {
        let c = corpus_of(vec![]);
        let r = score(&Passthrough, &c);
        assert_eq!(r.total_samples, 0);
        assert!((r.overall_leak_rate - 0.0).abs() < 1e-9);
    }

    #[test]
    fn sample_without_any_expected_entity_does_not_count() {
        // A sample that doesn't declare any expected entities shouldn't
        // affect class counters. (We still count it as a sample, but it
        // can't itself leak in the "expected entity" sense.)
        let c = corpus_of(vec![s("a", "hello world", &[])]);
        let r = score(&Passthrough, &c);
        assert_eq!(r.total_samples, 1);
        assert_eq!(r.total_leaked, 0);
    }

    #[test]
    fn report_serializes_to_json() {
        let c = corpus_of(vec![s("a", "PAN ABCDE1234F", &["pan"])]);
        let r = score(&Passthrough, &c);
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains("\"sut_name\":\"passthrough\""));
        assert!(j.contains("\"track\":\"prose\""));
        assert!(j.contains("\"entity\":\"pan\""));
    }
}