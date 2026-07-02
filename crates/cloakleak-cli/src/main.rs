//! CloakLeak CLI.
//!
//! Usage:
//!   cloakleak run --sut <name> --track <prose|tool_json> [--corpus-root <dir>]
//!   cloakleak baselines --track <prose|tool_json> [--corpus-root <dir>]
//!
//! `--sut name` selects the system-under-test:
//!   - `passthrough`     — does no redaction (baseline, should score ~100% leak)
//!   - `perfect`         — replaces everything with *** (upper bound, 0% leak)
//!   - `cloakpipe-regex` — runs the regex-based redaction
//!
//! Exits 0 if overall_leak_rate == 0.0; otherwise 1. This makes it a
//! CI gate: a non-zero exit fails the build.

use anyhow::{Context, Result};
use cloakleak::{
    corpus::{Corpus, Track},
    score::score,
    sut::{Passthrough, PerfectEraser, Sut},
    CloakPipeRegexSut,
};
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("cloakleak: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let cmd = args.get(1).map(String::as_str).unwrap_or("help");
    match cmd {
        "run" => {
            let (sut_name, track) = parse_run_args(args)?;
            let corpus = load_corpus(track)?;
            let sut: Box<dyn Sut> = match sut_name.as_str() {
                "passthrough" => Box::new(Passthrough),
                "perfect" => Box::new(PerfectEraser),
                "cloakpipe-regex" => Box::new(CloakPipeRegexSut),
                other => anyhow::bail!("unknown --sut {other}"),
            };
            let report = score(&*sut, &corpus);
            let j = serde_json::to_string_pretty(&report)?;
            println!("{j}");
            if report.overall_leak_rate == 0.0 {
                Ok(ExitCode::from(0))
            } else {
                Ok(ExitCode::from(1))
            }
        }
        "baselines" => {
            let (_, track) = parse_run_args(args)?;
            let corpus = load_corpus(track)?;
            for sut_name in ["passthrough", "perfect", "cloakpipe-regex"] {
                let report = score(&*match sut_name {
                    "passthrough" => Box::new(Passthrough) as Box<dyn Sut>,
                    "perfect" => Box::new(PerfectEraser),
                    "cloakpipe-regex" => Box::new(CloakPipeRegexSut),
                    _ => unreachable!(),
                }, &corpus);
                println!(
                    "{:<16} overall_leak_rate={:.4}  ({} leaked / {} samples)",
                    sut_name,
                    report.overall_leak_rate,
                    report.total_leaked,
                    report.total_samples
                );
            }
            Ok(ExitCode::from(0))
        }
        "help" | "--help" | "-h" => {
            println!("{}", USAGE);
            Ok(ExitCode::from(0))
        }
        other => anyhow::bail!("unknown command {other}; try `cloakleak help`"),
    }
}

fn parse_run_args(args: &[String]) -> Result<(String, Track)> {
    let mut sut_name = String::from("cloakpipe-regex");
    let mut track = None;
    let mut corpus_root: Option<String> = None;
    let mut iter = args.iter().skip(2);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--sut" => {
                sut_name = iter
                    .next()
                    .context("--sut requires a value")?
                    .to_string();
            }
            "--track" => {
                let t = iter.next().context("--track requires a value")?;
                track = Some(match t.as_str() {
                    "prose" => Track::Prose,
                    "tool_json" => Track::ToolJson,
                    other => anyhow::bail!("unknown track {other}"),
                });
            }
            "--corpus-root" => {
                corpus_root = Some(iter.next().context("--corpus-root requires a value")?.to_string());
            }
            other => anyhow::bail!("unknown flag {other}"),
        }
    }
    let track = track.context("--track <prose|tool_json> required")?;
    std::env::set_var("CLOAKLEAK_CORPUS_ROOT_OVERRIDE", corpus_root.unwrap_or_default());
    Ok((sut_name, track))
}

fn load_corpus(track: Track) -> Result<Corpus> {
    // CARGO_MANIFEST_DIR for the CLI points at crates/cloakleak-cli/.
    // The corpus lives in the sibling cloakleak crate.
    let path = format!(
        "{}/../cloakleak/corpus/{}/sample.jsonl",
        env!("CARGO_MANIFEST_DIR"),
        track.dir_name()
    );
    Corpus::load_from_file(&path).with_context(|| format!("loading corpus {path}"))
}

const USAGE: &str = "\
cloakleak — public PII-leak benchmark

USAGE:
  cloakleak run --sut <name> --track <prose|tool_json>
  cloakleak baselines --track <prose|tool_json>

SUTS:
  passthrough       no redaction (baseline ~100% leak)
  perfect           full redaction (upper bound, 0% leak)
  cloakpipe-regex   regex redaction + class-shaped tokens

EXITS:
  0   zero leaks (or baselines command)
  1   one or more leaks (fail CI gate)
  2   usage error
";