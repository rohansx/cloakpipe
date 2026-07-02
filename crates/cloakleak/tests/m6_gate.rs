//! M6 gate test — runs the harness against the actual sample corpora.
//!
//! Two assertions that prove the harness works:
//! 1. Passthrough SUT over the prose corpus scores > 0% overall leak.
//! 2. PerfectEraser SUT over both corpora scores 0% across the board.
//!
//! Plus: per-entity leak counts for Passthrough equal the per-entity
//! sample counts for every entity present in the corpus (sanity
//! check that detection isn't silently dropping anything).

use cloakleak::{
    corpus::{Corpus, Track},
    score::score,
    sut::{Passthrough, PerfectEraser},
};

const CORPUS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/corpus");

fn load(track: Track) -> Corpus {
    let dir = match track {
        Track::Prose => "prose",
        Track::ToolJson => "tool_json",
    };
    let path = format!("{CORPUS_ROOT}/{dir}/sample.jsonl");
    Corpus::load_from_file(&path).expect("load corpus")
}

#[test]
fn prose_corpus_loads() {
    let c = load(Track::Prose);
    assert!(c.len() >= 5, "expected a non-trivial sample corpus");
}

#[test]
fn tool_json_corpus_loads() {
    let c = load(Track::ToolJson);
    assert!(c.len() >= 5, "expected a non-trivial sample corpus");
}

#[test]
fn passthrough_prose_leaks_everything() {
    let c = load(Track::Prose);
    let r = score(&Passthrough, &c);
    // Every sample that declares an expected entity must leak under
    // passthrough (which redacts nothing). Total leaked > 0 is the
    // load-bearing assertion.
    assert!(r.total_leaked > 0, "passthrough must leak something: {r:?}");
    for row in &r.per_entity {
        assert!(
            (row.leak_rate - 1.0).abs() < 1e-9,
            "passthrough must leak 100% per entity: row={row:?}"
        );
    }
}

#[test]
fn passthrough_tool_json_leaks_everything() {
    let c = load(Track::ToolJson);
    let r = score(&Passthrough, &c);
    assert!(r.total_leaked > 0, "passthrough must leak something: {r:?}");
}

#[test]
fn perfect_eraser_prose_zero_leaks() {
    let c = load(Track::Prose);
    let r = score(&PerfectEraser, &c);
    assert_eq!(r.total_leaked, 0, "perfect eraser must leak nothing: {r:?}");
    for row in &r.per_entity {
        assert_eq!(row.leaked, 0, "row leaked: {row:?}");
    }
}

#[test]
fn perfect_eraser_tool_json_zero_leaks() {
    let c = load(Track::ToolJson);
    let r = score(&PerfectEraser, &c);
    assert_eq!(r.total_leaked, 0, "perfect eraser must leak nothing: {r:?}");
}

#[test]
fn scoreboard_json_is_well_formed() {
    let c = load(Track::Prose);
    let r = score(&Passthrough, &c);
    let j = serde_json::to_string_pretty(&r).unwrap();
    // Spot-check the wire shape.
    assert!(j.contains("\"sut_name\": \"passthrough\""));
    assert!(j.contains("\"track\": \"prose\""));
    assert!(j.contains("\"per_entity\":"));
}

#[test]
fn every_entity_in_corpus_is_detected_by_passthrough() {
    // For each entity class present in the corpus's `expected_entities`,
    // assert the passthrough SUT registers at least one leak of that
    // class. This catches the failure mode where a regex is too narrow
    // and silently misses a fixture.
    let c = load(Track::ToolJson);
    let r = score(&Passthrough, &c);
    let mut seen_classes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for s in &c.samples {
        for e in &s.expected_entities {
            seen_classes.insert(e.clone());
        }
    }
    for class in &seen_classes {
        let row = r.per_entity.iter().find(|r| &r.entity == class);
        assert!(
            row.is_some(),
            "entity {class} declared in corpus but no score row produced — \
             either regex is broken or sample fixtures are wrong"
        );
        let row = row.unwrap();
        assert_eq!(
            row.leaked, row.samples,
            "passthrough must leak 100% of {class} samples"
        );
    }
}