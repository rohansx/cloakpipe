//! The draft as a `cloakpipe.manifest.yaml`, with its evidence as comments.
//!
//! Comments do not change the manifest digest, so the evidence can stay in
//! the file a person reviews and later activates.

use std::fmt::Write as _;

use super::draft::{Arg, Draft, Spec, Tool};

/// Header facts that are not part of the draft itself.
pub struct Header<'a> {
    pub release: &'a str,
    pub date: &'a str,
    /// `(passed, checked)` kept calls that pass the draft; `None` when the
    /// captures are shapes only and the check cannot run.
    pub self_check: Option<(usize, usize)>,
}

pub fn render(d: &Draft, h: &Header) -> String {
    let mut out = String::new();
    let w = &mut out;
    let _ = writeln!(w, "# DRAFT contract from `cloakpipe infer`: {} calls in {} session(s), {}.", d.calls, d.sessions, h.date);
    let _ = writeln!(w, "# NOT ACTIVE. Review every rule and decide every SUGGESTED line, then run it");
    let _ = writeln!(w, "# with `cloakpipe mcp-proxy --manifest <this file>` (shadow mode first).");
    if d.shapes {
        let _ = writeln!(w, "# Captured as shapes only: string values were never stored, so no enums, domains or hosts.");
    }
    match h.self_check {
        Some((pass, total)) => {
            let _ = writeln!(w, "# Self-check: {pass}/{total} captured calls pass this draft (outliers are listed below).");
        }
        None => {
            let _ = writeln!(w, "# Self-check: skipped (shape-only captures).");
        }
    }
    if !d.review.is_empty() {
        let _ = writeln!(w, "#\n# REVIEW before activating:");
        for r in &d.review {
            let _ = writeln!(w, "#   - {r}");
        }
    }
    let _ = writeln!(w, "release: {}", key(h.release));
    let _ = writeln!(w, "version: \"draft-{}\"", h.date);
    if d.tools.is_empty() {
        let _ = writeln!(w, "tools: {{}}");
    } else {
        let _ = writeln!(w, "tools:");
        for t in &d.tools {
            tool(w, t);
        }
    }
    if !d.undeclared.is_empty() {
        let _ = writeln!(w, "# NOT DECLARED (offered by the server, never called): {}", d.undeclared.join(", "));
    }
    out
}

fn tool(w: &mut String, t: &Tool) {
    let excluded = if t.excluded > 0 { format!(", {} outlier(s) excluded", t.excluded) } else { String::new() };
    let _ = writeln!(w, "  # {} call(s){excluded}", t.calls);
    let drafted: Vec<(&String, &Arg)> = t.args.iter().filter(|(_, a)| restricts(&a.spec)).collect();
    if drafted.is_empty() && !t.side_effect && t.approval.is_none() && t.args.is_empty() {
        let _ = writeln!(w, "  {}: {{}}", key(&t.name));
        return;
    }
    let _ = writeln!(w, "  {}:", key(&t.name));
    if !drafted.is_empty() {
        let _ = writeln!(w, "    args:");
        for (name, a) in &drafted {
            let _ = writeln!(w, "      # {}", a.note);
            let _ = writeln!(w, "      {}: {}", key(name), flow(&a.spec, a.required));
        }
    }
    for (name, a) in t.args.iter().filter(|(_, a)| !restricts(&a.spec)) {
        let _ = writeln!(w, "    # NOT DRAFTED: {name} ({}): calls carrying it are refused until you write its rule", a.note);
    }
    if t.side_effect {
        let _ = writeln!(w, "    # Guessed from the tool name: tracked as an operation (needs --operations-db).");
        let _ = writeln!(w, "    side_effect: true");
    }
    if let Some(when) = &t.approval {
        let _ = writeln!(w, "    # SUGGESTED: require approval near the top of the observed values. Decide before activating.");
        let _ = writeln!(w, "    # approval: {{ when: {}, approvers: [\"<route>\"], ttl: 15m }}", json(when));
    }
}

/// A constraint that restricts nothing would not load; it is left out.
fn restricts(s: &Spec) -> bool {
    s.ty.is_some() || s.one_of.is_some() || s.pattern.is_some() || !s.one_of_context.is_empty() || s.max_len.is_some()
}

/// One constraint as a YAML flow mapping.
pub fn flow(s: &Spec, required: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = s.ty {
        parts.push(format!("type: {t}"));
    }
    if !s.one_of_context.is_empty() {
        parts.push(format!("one_of_context: [{}]", s.one_of_context.iter().map(|p| json(p)).collect::<Vec<_>>().join(", ")));
    }
    if let Some(p) = &s.or_pattern {
        parts.push(format!("or_pattern: {}", json(p)));
    }
    if let Some(e) = &s.one_of {
        parts.push(format!("enum: {}", serde_json::to_string(e).unwrap_or_default()));
    }
    if let Some(p) = &s.pattern {
        parts.push(format!("pattern: {}", json(p)));
    }
    if let Some(n) = &s.min {
        parts.push(format!("min: {n}"));
    }
    if let Some(n) = &s.max {
        parts.push(format!("max: {n}"));
    }
    if let Some(n) = s.max_len {
        parts.push(format!("max_len: {n}"));
    }
    if let Some(items) = s.items.as_deref().filter(|i| restricts(i)) {
        parts.push(format!("items: {}", flow(items, false)));
    }
    if let Some(props) = &s.properties {
        let inner: Vec<String> =
            props.iter().filter(|(_, a)| restricts(&a.spec)).map(|(k, a)| format!("{}: {}", json(k), flow(&a.spec, a.required))).collect();
        parts.push(format!("properties: {{ {} }}", inner.join(", ")));
    }
    if required {
        parts.push("required: true".into());
    }
    format!("{{ {} }}", parts.join(", "))
}

fn json(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_default()
}

/// A mapping key: bare when it is a plain identifier, quoted otherwise.
fn key(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && s.as_bytes()[0].is_ascii_alphabetic()
        && !matches!(s, "true" | "false" | "null" | "yes" | "no" | "on" | "off" | "y" | "n");
    if plain { s.to_string() } else { json(s) }
}
