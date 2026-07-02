//! Public sample corpus.
//!
//! Per the CloakLeak design (`docs/v2/09-CLOAKLEAK.md` §3):
//! - Public repo carries the **harness + sample corpus** (Apache-2.0 / CC-BY-4.0).
//! - The **full validation set is held out** in a private repo; published
//!   scores are produced against the held-out set, never the public one.
//!
//! Format: JSON Lines (one sample per line) at:
//! - `corpus/prose/sample.jsonl`
//! - `corpus/tool_json/sample.jsonl`
//!
//! Schema per sample:
//! ```json
//! { "id": "prose-001", "track": "prose", "input": "...", "expected_entities": ["pan", "aadhaar"] }
//! ```
//!
//! `expected_entities` is a list of *classes* expected to be present in
//! the input. The leak score is: did the SUT let any of those classes
//! through?

use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Track {
    Prose,
    ToolJson,
}

impl Track {
    pub fn dir_name(&self) -> &'static str {
        match self {
            Track::Prose => "prose",
            Track::ToolJson => "tool_json",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub id: String,
    pub track: Track,
    pub input: String,
    /// Slugs of [`crate::detect::EntityClass`] expected to appear in the
    /// *input*. The leak score is per-class.
    pub expected_entities: Vec<String>,
    /// Optional modality tag — e.g. "hinglish", "email_body", "mcp_args".
    /// Used to slice the scoreboard, not to gate scoring.
    #[serde(default)]
    pub modality: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Corpus {
    pub track: Track,
    pub samples: Vec<Sample>,
}

impl Corpus {
    /// Load a corpus from a JSONL file at `path`.
    pub fn load_from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bytes = std::fs::read(path.as_ref())?;
        let mut samples = Vec::new();
        for (lineno, line) in bytes.split(|&b| b == b'\n').enumerate() {
            if line.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            let s: Sample = serde_json::from_slice(line)
                .map_err(|e| anyhow::anyhow!("line {}: {}", lineno + 1, e))?;
            samples.push(s);
        }
        let track = samples.first().map(|s| s.track).unwrap_or(Track::Prose);
        Ok(Self { track, samples })
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn round_trip_sample() {
        let s = Sample {
            id: "p-1".into(),
            track: Track::Prose,
            input: "PAN ABCDE1234F".into(),
            expected_entities: vec!["pan".into()],
            modality: None,
        };
        let j = serde_json::to_string(&s).unwrap();
        let back: Sample = serde_json::from_str(&j).unwrap();
        assert_eq!(back.id, s.id);
    }

    #[test]
    fn loads_jsonl_skipping_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sample.jsonl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"{{"id":"a","track":"prose","input":"PAN ABCDE1234F","expected_entities":["pan"]}}"#
        )
        .unwrap();
        writeln!(f).unwrap(); // blank line
        writeln!(
            f,
            r#"{{"id":"b","track":"prose","input":"phone 9876543210","expected_entities":["phone"]}}"#
        )
        .unwrap();
        drop(f);
        let c = Corpus::load_from_file(&path).unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c.track, Track::Prose);
    }
}