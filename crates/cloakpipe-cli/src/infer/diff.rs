//! `infer --diff <manifest>`: captured traffic against the active contract.
//!
//! - **new tools**: called, but not declared (each is refused in enforce);
//! - **drift**: calls the contract refuses, grouped by tool, reason and path;
//! - **tighten**: rules looser than what was observed;
//! - **unused**: declared tools never called, arguments never sent.
//!
//! Drift or a new tool fails the check (exit 1), so it can gate CI.

use cloakpipe_release::contract::Constraint;
use cloakpipe_release::v1::Manifest;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::draft::{self, Draft};
use super::load::Session;
use super::redact;

#[derive(Debug, Default)]
pub struct Report {
    pub calls: usize,
    /// Calls not checked: captured as shapes.
    pub skipped: usize,
    pub new_tools: BTreeMap<String, usize>,
    /// `(tool, reason, path)` -> (calls, one redacted example).
    pub drift: BTreeMap<(String, String, String), (usize, String)>,
    pub tighten: Vec<String>,
    pub unused: Vec<String>,
}

impl Report {
    pub fn failed(&self) -> bool {
        !self.new_tools.is_empty() || !self.drift.is_empty()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "calls": self.calls,
            "skipped": self.skipped,
            "ok": !self.failed(),
            "new_tools": self.new_tools,
            "drift": self.drift.iter().map(|((tool, reason, path), (n, ex))| json!({
                "tool": tool, "reason": reason, "path": (!path.is_empty()).then_some(path), "calls": n, "example": ex,
            })).collect::<Vec<_>>(),
            "tighten": self.tighten,
            "unused": self.unused,
        })
    }

    pub fn to_text(&self) -> String {
        let mut out = format!("{} call(s) checked against the contract", self.calls - self.skipped);
        if self.skipped > 0 {
            out.push_str(&format!(" ({} shape-only calls skipped)", self.skipped));
        }
        out.push('\n');
        let mut section = |title: &str, lines: Vec<String>| {
            if !lines.is_empty() {
                out.push_str(&format!("\n{title}:\n"));
                for l in lines {
                    out.push_str(&format!("  - {l}\n"));
                }
            }
        };
        section("NEW TOOLS (not declared: refused in enforce mode)", self.new_tools.iter().map(|(t, n)| format!("{t}: {n} call(s)")).collect());
        section(
            "DRIFT (calls the contract refuses)",
            self.drift
                .iter()
                .map(|((t, r, p), (n, ex))| format!("{t}{}: {r}, {n} call(s); e.g. {ex}", if p.is_empty() { String::new() } else { format!(" {p}") }))
                .collect(),
        );
        section("COULD BE TIGHTENED", self.tighten.clone());
        section("UNUSED", self.unused.clone());
        out.push_str(if self.failed() { "\nresult: DRIFT\n" } else { "\nresult: OK\n" });
        out
    }
}

pub fn diff(manifest: &Manifest, sessions: &[Session], observed: &Draft) -> Report {
    let mut r = Report::default();
    let mut called: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for s in sessions {
        for c in &s.calls {
            r.calls += 1;
            let sent = called.entry(c.tool.as_str()).or_default();
            sent.extend(c.args.as_ref().and_then(Value::as_object).into_iter().flat_map(|o| o.keys().map(String::as_str)));
            let Some(rule) = manifest.rule(&c.tool) else {
                *r.new_tools.entry(c.tool.clone()).or_default() += 1;
                continue;
            };
            if s.shapes {
                r.skipped += 1;
                continue;
            }
            if let Err(v) = rule.check(c.args.as_ref(), s.task.as_ref()) {
                let path = v.path.clone().unwrap_or_default();
                let example = c.args.as_ref().and_then(|a| a.pointer(&path)).map(redact::example).unwrap_or_else(|| "-".into());
                let e = r.drift.entry((c.tool.clone(), v.code.code().to_string(), path)).or_insert((0, example));
                e.0 += 1;
            }
        }
    }
    for (tool, rule) in manifest.tools() {
        let Some(sent) = called.get(tool.as_str()) else {
            r.unused.push(format!("{tool}: declared, never called (remove it to refuse it)"));
            continue;
        };
        for arg in rule.arguments.keys().filter(|a| !sent.contains(a.as_str())) {
            r.unused.push(format!("{tool}.{arg}: declared, never sent"));
        }
    }
    for t in &observed.tools {
        let Some(rule) = manifest.rule(&t.name) else { continue };
        for (arg, seen) in &t.args {
            if let Some(c) = rule.arguments.get(arg) {
                tighten(&format!("{}.{arg}", t.name), c, &seen.spec, &mut r.tighten);
            }
        }
    }
    r
}

/// Where the contract is much looser than what was observed.
fn tighten(at: &str, c: &Constraint, seen: &draft::Spec, out: &mut Vec<String>) {
    let f = |n: &serde_json::Number| n.as_f64().unwrap_or(0.0);
    if let (Some(declared), Some(observed)) = (&c.maximum, &seen.max) {
        if f(declared) > 2.0 * f(observed).max(1.0) {
            out.push(format!("{at}: max {declared}, observed traffic fits max {observed}"));
        }
    }
    if let (Some(declared), Some(observed)) = (c.max_length, seen.max_len) {
        if declared > 2 * observed.max(1) {
            out.push(format!("{at}: max_len {declared}, observed traffic fits max_len {observed}"));
        }
    }
    let open = c.one_of_context.is_none() && c.one_of.is_none() && c.constant.is_none();
    if open && !seen.one_of_context.is_empty() {
        out.push(format!("{at}: every call equals task.{}: consider one_of_context", seen.one_of_context.join(", task.")));
    } else if open && c.pattern.is_none() {
        if let Some(values) = &seen.one_of {
            out.push(format!("{at}: only {} distinct values observed: consider an enum", values.len()));
        }
    }
}
