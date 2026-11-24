//! `cloakpipe infer`: draft a contract from captured tool calls, or diff
//! captured traffic against the active one.
//!
//! ```text
//! cloakpipe mcp-proxy --capture ./captures/ --upstream … [--manifest m.yaml --mode shadow]
//! cloakpipe infer ./captures/ --out cloakpipe.manifest.draft.yaml
//! cloakpipe infer ./captures/ --diff cloakpipe.manifest.yaml     # CI: exit 1 on drift
//! ```
//!
//! The draft is a normal v1 manifest, never activated: every rule carries a
//! comment with its support, confidence and a redacted example, and a review
//! list at the top names low-support rules, excluded outliers, suggested
//! approvals and tools left undeclared. Before it is written, the draft is
//! loaded with the gate's own parser and every captured call is checked
//! against it.
//!
//! Exit codes: 0 drafted / no drift, 1 drift found or a capture is
//! malformed, 2 usage or I/O error.

mod diff;
pub(crate) mod draft;
pub(crate) mod load;
mod redact;
mod render;

use crate::keys::{invalid, usage, Res};
use crate::release::{EXIT_INVALID, EXIT_OK};
use clap::Args;
use cloakpipe_release::v1::Manifest;
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct InferArgs {
    /// Capture files, or directories of them (`mcp-proxy --capture <dir>`)
    #[arg(required = true)]
    pub captures: Vec<PathBuf>,
    /// Write the draft here instead of stdout (refuses to overwrite without --force)
    #[arg(long, conflicts_with = "diff")]
    pub out: Option<PathBuf>,
    /// Overwrite --out
    #[arg(long, requires = "out")]
    pub force: bool,
    /// Compare the captures against this manifest instead: new tools, calls
    /// it refuses, rules that could be tightened. Exits 1 on drift (for CI).
    #[arg(long, value_name = "MANIFEST")]
    pub diff: Option<PathBuf>,
    /// With --diff: print the report as JSON
    #[arg(long, requires = "diff")]
    pub json: bool,
    /// The draft's release name
    #[arg(long, default_value = "draft-agent")]
    pub release: String,
    /// Calls an argument needs before more than its type and exact bounds is drafted
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..))]
    pub min_support: u64,
    /// Share of calls that must equal a task-context field for a task binding (0.5 to 1)
    #[arg(long, default_value_t = 0.9)]
    pub bind_threshold: f64,
    /// Delete the capture files once the draft is written
    #[arg(long, conflicts_with = "diff")]
    pub delete_after: bool,
}

pub fn run(a: InferArgs) -> i32 {
    crate::keys::finish(run_inner(&a))
}

fn run_inner(a: &InferArgs) -> Res<i32> {
    if !(0.5..=1.0).contains(&a.bind_threshold) {
        return Err(usage("--bind-threshold must be between 0.5 and 1"));
    }
    let files = load::capture_files(&a.captures).map_err(usage)?;
    let sessions = files.iter().map(|f| load::read(f)).collect::<Result<Vec<_>, _>>().map_err(invalid)?;
    let opts = draft::Options { min_support: a.min_support as usize, bind_threshold: a.bind_threshold };
    let drafted = draft::infer(&sessions, &opts);

    if let Some(path) = &a.diff {
        let manifest = Manifest::parse_path(path).map_err(|e| invalid(format_args!("{}: {e}", path.display())))?;
        let report = diff::diff(&manifest, &sessions, &drafted);
        if a.json {
            println!("{}", serde_json::to_string_pretty(&report.to_json()).unwrap_or_default());
        } else {
            print!("{}", report.to_text());
        }
        return Ok(if report.failed() { EXIT_INVALID } else { EXIT_OK });
    }

    let date = chrono::Utc::now().format("%Y-%m-%d").to_string();
    // Load the draft with the gate's own parser: a draft that would not
    // load is a bug here, never something to hand a person.
    let first = render::render(&drafted, &render::Header { release: &a.release, date: &date, self_check: None });
    let manifest = Manifest::parse_str(&first, Path::new("."))
        .map_err(|e| invalid(format_args!("the drafted contract does not load ({e}); this is a bug in cloakpipe infer")))?;
    let self_check = (!drafted.shapes).then(|| self_check(&manifest, &sessions));
    let text = render::render(&drafted, &render::Header { release: &a.release, date: &date, self_check });

    match &a.out {
        None => print!("{text}"),
        Some(out) => {
            if out.exists() && !a.force {
                return Err(usage(format_args!("{} exists (use --force to overwrite)", out.display())));
            }
            std::fs::write(out, &text).map_err(|e| usage(format_args!("{}: {e}", out.display())))?;
            eprintln!(
                "drafted {} tool(s) from {} call(s) in {} session(s): {} (NOT ACTIVE; {} item(s) to review)",
                drafted.tools.len(),
                drafted.calls,
                drafted.sessions,
                out.display(),
                drafted.review.len()
            );
        }
    }
    if a.delete_after {
        for f in &files {
            std::fs::remove_file(f).map_err(|e| usage(format_args!("--delete-after {}: {e}", f.display())))?;
        }
        eprintln!("deleted {} capture file(s)", files.len());
    }
    Ok(EXIT_OK)
}

/// `(passed, checked)`: captured calls the draft lets through.
fn self_check(m: &Manifest, sessions: &[load::Session]) -> (usize, usize) {
    let mut pass = 0;
    let mut total = 0;
    for s in sessions {
        for c in &s.calls {
            total += 1;
            if m.rule(&c.tool).is_some_and(|r| r.check(c.args.as_ref(), s.task.as_ref()).is_ok()) {
                pass += 1;
            }
        }
    }
    (pass, total)
}
