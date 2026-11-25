//! The inference engine: observed calls in, a draft contract out.
//!
//! Pure functions over [`Session`]s, so the rules are testable without a
//! proxy. Safety rules (spec "infer + prove", §3):
//!
//! - **Observed is not legitimate.** A call whose value breaks the pattern
//!   the rest follow (a recipient that is neither the task's nor a recurring
//!   domain, an amount or a length ten times the median) is an *outlier*: it
//!   is excluded from every rule of its tool and listed for review, never
//!   widened into the rule.
//! - **Minimum support.** Below `min_support` calls an argument gets only its
//!   type and the exact observed bounds, and is flagged.
//! - **Tight by default.** Bounds carry a small margin; strings get an enum,
//!   a pattern or a task binding when the evidence allows one.
//! - Approvals are only ever *suggested*.

use serde_json::{Number, Value};
use std::collections::{BTreeMap, BTreeSet};

use super::load::{shape_of, Session};
use super::redact;

/// Inference knobs.
#[derive(Debug, Clone)]
pub struct Options {
    /// Calls an argument needs before anything but its type and exact
    /// bounds is drafted.
    pub min_support: usize,
    /// Share of calls (not covered by an `or_pattern` group) whose value
    /// must equal a task-context field for a binding.
    pub bind_threshold: f64,
}

impl Default for Options {
    fn default() -> Self {
        Self { min_support: 5, bind_threshold: 0.9 }
    }
}

/// What to write for one value: the manifest's argument keys.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Spec {
    pub ty: Option<&'static str>,
    pub one_of: Option<Vec<Value>>,
    pub pattern: Option<String>,
    pub max_len: Option<u64>,
    pub min: Option<Number>,
    pub max: Option<Number>,
    pub one_of_context: Vec<String>,
    pub or_pattern: Option<String>,
    pub properties: Option<BTreeMap<String, Arg>>,
    pub items: Option<Box<Spec>>,
}

/// One drafted argument: its rule and the evidence comment.
#[derive(Debug, Clone, PartialEq)]
pub struct Arg {
    pub spec: Spec,
    pub required: bool,
    pub note: String,
}

/// One drafted tool.
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    /// Calls observed, and how many were excluded as outliers.
    pub calls: usize,
    pub excluded: usize,
    pub args: BTreeMap<String, Arg>,
    /// Guessed from the name (sends, pays, deletes, …).
    pub side_effect: bool,
    /// A suggested approval condition, never active.
    pub approval: Option<String>,
}

/// The draft and its review list.
#[derive(Debug, Clone, Default)]
pub struct Draft {
    pub tools: Vec<Tool>,
    /// Offered by a server, never called: left undeclared.
    pub undeclared: Vec<String>,
    /// What a person must look at before activating the draft.
    pub review: Vec<String>,
    pub sessions: usize,
    pub calls: usize,
    pub shapes: bool,
}

const MONEY_TOOL: &[&str] = &["refund", "pay", "charge", "transfer", "invoice", "withdraw", "wire", "credit", "payout"];
const DATA_OUT_TOOL: &[&str] = &["export", "dump", "download", "share", "forward"];
const SIDE_EFFECT_TOOL: &[&str] = &[
    "send", "create", "update", "delete", "remove", "issue", "refund", "pay", "charge", "transfer", "post", "write", "cancel", "close",
    "invoice", "export", "set", "add", "book",
];
const AMOUNT_ARG: &[&str] = &["amount", "total", "price", "sum", "value", "quantity", "qty", "count", "limit"];

/// Draft a contract from what was observed.
pub fn infer(sessions: &[Session], opts: &Options) -> Draft {
    let mut by_tool: BTreeMap<&str, Vec<(usize, Option<&Value>)>> = BTreeMap::new();
    let mut offered = BTreeSet::new();
    for (s, session) in sessions.iter().enumerate() {
        offered.extend(session.offered.keys().map(String::as_str));
        for call in &session.calls {
            by_tool.entry(call.tool.as_str()).or_default().push((s, call.args.as_ref()));
        }
    }
    let mut draft = Draft {
        sessions: sessions.len(),
        calls: by_tool.values().map(Vec::len).sum(),
        shapes: sessions.iter().any(|s| s.shapes),
        ..Draft::default()
    };
    let forged: usize = sessions.iter().map(|s| s.forged).sum();
    if forged > 0 {
        draft.review.push(format!("excluded {forged} call(s) whose arguments posed as capture shapes (only an agent could send those)"));
    }
    for (name, calls) in &by_tool {
        draft.tools.push(infer_tool(name, calls, sessions, opts, &mut draft.review));
    }
    draft.undeclared = offered.into_iter().filter(|t| !by_tool.contains_key(t)).map(str::to_string).collect();
    for t in &draft.undeclared {
        draft.review.push(format!("not declared: {t} (offered by the server, never called; it will be refused)"));
    }
    draft
}

fn infer_tool(name: &str, calls: &[(usize, Option<&Value>)], sessions: &[Session], opts: &Options, review: &mut Vec<String>) -> Tool {
    let n = calls.len();
    let low = n < opts.min_support;
    if low {
        review.push(format!("low support: {name} was called {n} time(s) (< {}): its arguments have exact observed bounds only", opts.min_support));
    }
    // Pass 1: which calls are outliers.
    let names: BTreeSet<&str> = calls.iter().filter_map(|(_, a)| a.and_then(Value::as_object)).flat_map(|o| o.keys().map(String::as_str)).collect();
    let mut outliers: BTreeMap<usize, String> = BTreeMap::new();
    if !low {
        for arg in &names {
            let values: Vec<(usize, usize, &Value)> =
                calls.iter().enumerate().filter_map(|(i, (s, a))| Some((i, *s, (*a)?.get(*arg)?))).collect();
            for (i, why) in find_outliers(arg, &values, sessions, opts) {
                outliers.entry(i).or_insert(why);
            }
        }
    }
    if outliers.len() == n {
        outliers.clear(); // Nothing left to learn from: keep them all, flagged by low confidence.
    }
    for (i, why) in &outliers {
        review.push(format!("outlier excluded: {name} call #{} ({why})", i + 1));
    }
    // Pass 2: rules from the calls that remain.
    let kept: Vec<(usize, Option<&Value>)> = calls.iter().enumerate().filter(|(i, _)| !outliers.contains_key(i)).map(|(_, c)| *c).collect();
    let mut args = BTreeMap::new();
    for arg in names {
        let values: Vec<(usize, &Value)> = kept.iter().filter_map(|(s, a)| Some((*s, (*a)?.get(arg)?))).collect();
        if values.is_empty() {
            continue; // Only outliers sent it: left undeclared.
        }
        let required = values.len() == kept.len();
        let ctx = Ctx { tool: name, path: arg.to_string(), sessions, opts, calls: kept.len() };
        let (spec, note) = infer_value(&ctx, &values, review);
        args.insert(arg.to_string(), Arg { spec, required, note });
    }
    let lname = name.to_ascii_lowercase();
    let side_effect = SIDE_EFFECT_TOOL.iter().any(|v| lname.contains(v));
    let approval = suggest_approval(&lname, &args, &kept);
    if let Some(when) = &approval {
        review.push(format!("suggested approval: {name} when {when} (commented out: decide before activating)"));
    } else if DATA_OUT_TOOL.iter().any(|v| lname.contains(v)) {
        review.push(format!("suggested approval: {name} looks like it moves data out: consider an approval block"));
    }
    Tool { name: name.to_string(), calls: n, excluded: outliers.len(), args, side_effect, approval }
}

/// An approval condition near the top of the observed values, for a tool
/// that looks like it moves money.
fn suggest_approval(lname: &str, args: &BTreeMap<String, Arg>, kept: &[(usize, Option<&Value>)]) -> Option<String> {
    if !MONEY_TOOL.iter().any(|v| lname.contains(v)) {
        return None;
    }
    let (arg, spec) = args.iter().find(|(a, spec)| {
        matches!(spec.spec.ty, Some("integer" | "number")) && AMOUNT_ARG.iter().any(|w| a.to_ascii_lowercase().contains(w))
    })?;
    let top = kept.iter().filter_map(|(_, a)| (*a)?.get(arg)?.as_f64()).fold(f64::MIN, f64::max);
    // A threshold at or above the drafted max could never fire: round finer.
    let max = spec.spec.max.as_ref().and_then(Number::as_f64).unwrap_or(f64::INFINITY);
    let at = Some(nice_ceil(top, 1)).filter(|t| *t < max).unwrap_or_else(|| nice_ceil(top, 2));
    (top > 0.0).then(|| format!("{arg} > {}", fmt_num(at)))
}

struct Ctx<'a> {
    tool: &'a str,
    /// The argument's path, for messages (`to`, `customer.email`).
    path: String,
    sessions: &'a [Session],
    opts: &'a Options,
    /// Calls the tool kept (the denominator for support).
    calls: usize,
}

/// Infer one value's rule from its observations `(session, value)`.
fn infer_value(ctx: &Ctx, values: &[(usize, &Value)], review: &mut Vec<String>) -> (Spec, String) {
    let n = values.len();
    let low = n < ctx.opts.min_support;
    let support = format!("{n}/{} calls", ctx.calls);
    let confidence = if low { "low" } else if n >= 4 * ctx.opts.min_support { "high" } else { "medium" };
    let Some(ty) = unify(values.iter().map(|(_, v)| *v)) else {
        review.push(format!("mixed types: {}.{} takes values of several types: left untyped, write its rule by hand", ctx.tool, ctx.path));
        return (Spec::default(), format!("{support}, mixed types"));
    };
    let mut spec = Spec { ty: Some(ty), ..Spec::default() };
    let note = match ty {
        "string" => infer_string(ctx, values, &mut spec, review, low),
        "integer" | "number" => {
            let nums: Vec<f64> = values.iter().filter_map(|(_, v)| v.as_f64()).collect();
            let (lo, hi) = (nums.iter().copied().fold(f64::MAX, f64::min), nums.iter().copied().fold(f64::MIN, f64::max));
            let integer = ty == "integer";
            let (min, max) = if low { (lo, hi) } else { (if lo >= 0.0 { 0.0 } else { -nice_ceil(-lo * 1.25, 2) }, nice_ceil(hi * 1.25, 2)) };
            spec.min = number(min, integer);
            spec.max = number(max, integer);
            format!("range seen {} to {}", fmt_num(lo), fmt_num(hi))
        }
        "boolean" => {
            let seen: BTreeSet<bool> = values.iter().filter_map(|(_, v)| v.as_bool()).collect();
            if !low && seen.len() == 1 {
                spec.one_of = Some(seen.iter().map(|b| Value::Bool(*b)).collect());
            }
            format!("seen {}", seen.iter().map(bool::to_string).collect::<Vec<_>>().join(", "))
        }
        "object" => {
            let mut props = BTreeMap::new();
            let keys: BTreeSet<&str> = values.iter().filter_map(|(_, v)| v.as_object()).flat_map(|o| o.keys().map(String::as_str)).collect();
            for key in keys {
                let sub: Vec<(usize, &Value)> = values.iter().filter_map(|(s, v)| Some((*s, v.get(key)?))).collect();
                let child = Ctx { path: format!("{}.{key}", ctx.path), calls: n, ..*ctx };
                let (s, note) = infer_value(&child, &sub, review);
                props.insert(key.to_string(), Arg { spec: s, required: sub.len() == n, note });
            }
            spec.properties = Some(props);
            "closed object: only these members".to_string()
        }
        _ => {
            let items: Vec<(usize, &Value)> = values.iter().flat_map(|(s, v)| v.as_array().into_iter().flatten().map(move |x| (*s, x))).collect();
            let longest = values.iter().filter_map(|(_, v)| v.as_array().map(Vec::len)).max().unwrap_or(0) as f64;
            spec.max_len = Some(if low { longest } else { nice_ceil(longest * 1.25, 1).max(1.0) } as u64);
            if !items.is_empty() {
                let child = Ctx { path: format!("{}[]", ctx.path), calls: items.len(), ..*ctx };
                spec.items = Some(Box::new(infer_value(&child, &items, review).0));
            }
            format!("up to {longest} items seen")
        }
    };
    match note.strip_prefix(BOUND) {
        // A binding states its own confidence.
        Some(bound) => (spec, format!("{support}; {bound}")),
        None => (spec, format!("{support}, {confidence} confidence; {note}")),
    }
}

/// Marks a binding's note, which carries its own confidence.
const BOUND: &str = "\u{1}";

fn infer_string(ctx: &Ctx, values: &[(usize, &Value)], spec: &mut Spec, review: &mut Vec<String>, low: bool) -> String {
    let n = values.len();
    let longest = values.iter().map(|(_, v)| str_len(v)).max().unwrap_or(0);
    let example = redact::example(values[0].1);
    let shaped = values.iter().any(|(_, v)| shape_of(v).is_some());
    if let Some(b) = bind(ctx, values) {
        let (total, matched) = (n - b.or_covered, b.matched);
        let distinct: BTreeSet<String> = values.iter().filter_map(|(_, v)| key(v)).collect();
        let confidence = if distinct.len() < 2 { "low (one value observed)" } else if matched == total { "high" } else { "medium" };
        if distinct.len() < 2 {
            review.push(format!("weak binding: {}.{} equals task.{} in every call, but only one task was observed", ctx.tool, ctx.path, b.path));
        }
        spec.one_of_context = vec![b.path.clone()];
        let mut note = format!("{BOUND}must equal task.{} ({matched}/{total} calls)", b.path);
        if let Some(p) = &b.or_pattern {
            review.push(format!("or_pattern: {}.{} also accepts {p} ({} calls): confirm these addresses are yours", ctx.tool, ctx.path, b.or_covered));
            spec.or_pattern = Some(p.clone());
            note.push_str(&format!(" or match {p} ({} calls)", b.or_covered));
        }
        return format!("{note}; {confidence} confidence");
    }
    if shaped {
        review.push(format!("shape-only: {}.{} was captured as shapes: no enum, domain or host can be drafted", ctx.tool, ctx.path));
    }
    let raw: Vec<&str> = values.iter().filter_map(|(_, v)| v.as_str()).collect();
    let distinct: BTreeSet<&str> = raw.iter().copied().collect();
    let classes: BTreeSet<String> = values.iter().map(|(_, v)| class_of(v)).collect();
    let single_class = (classes.len() == 1).then(|| classes.iter().next().cloned()).flatten();
    // Never an enum of free text or of identifying values (addresses, ids).
    let enumerable = !matches!(single_class.as_deref(), Some("text" | "email" | "id" | "uuid" | "digits" | "url"));
    if !low && !shaped && enumerable && distinct.len() <= 6 && n >= 3 * distinct.len() {
        spec.one_of = Some(distinct.iter().map(|s| Value::String(s.to_string())).collect());
        return format!("{} distinct values, {n} calls", distinct.len());
    }
    if !low {
        if let Some(p) = single_class.as_deref().and_then(|c| pattern_for(c, values, &raw, shaped)) {
            spec.pattern = Some(p);
            return format!("all {}; e.g. {example}", single_class.unwrap_or_default());
        }
    }
    spec.max_len = Some(if low { longest as u64 } else { nice_ceil(longest as f64 * 1.15, 1) as u64 }.max(1));
    format!("longest seen {longest}; e.g. {example}")
}

/// A pattern when every value is of class `class`, if that class has one.
fn pattern_for(class: &str, values: &[(usize, &Value)], raw: &[&str], shaped: bool) -> Option<String> {
    match class {
        "id" => {
            let prefixes: BTreeSet<String> = values.iter().filter_map(|(_, v)| id_prefix(v)).collect();
            let digits = values.iter().map(|(_, v)| str_len(v).saturating_sub(id_prefix(v).map_or(0, |p| p.chars().count()))).min()?.max(1);
            let prefix = prefixes.iter().next().filter(|_| prefixes.len() == 1)?;
            Some(format!("{}[0-9]{{{digits},}}", regex::escape(prefix)))
        }
        "uuid" => Some("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".into()),
        "digits" => {
            let lens: BTreeSet<usize> = values.iter().map(|(_, v)| str_len(v)).collect();
            Some(format!("[0-9]{{{},{}}}", lens.first()?, lens.last()?))
        }
        "email" if !shaped => {
            let domains: BTreeSet<&str> = raw.iter().filter_map(|s| s.rsplit_once('@').map(|(_, d)| d)).collect();
            (domains.len() <= 3).then(|| format!("[^@\\s]+@({})", alternation(&domains)))
        }
        "url" if !shaped => {
            let hosts: BTreeSet<&str> = raw.iter().filter_map(|s| s.strip_prefix("https://").map(|r| r.split(['/', '?', '#']).next().unwrap_or(r))).collect();
            (hosts.len() == raw.len().min(hosts.len()) && !hosts.is_empty() && hosts.len() <= 3 && raw.iter().all(|s| s.starts_with("https://")))
                .then(|| format!("https://({})([/?#].*)?", alternation(&hosts)))
        }
        _ => None,
    }
}

fn alternation(items: &BTreeSet<&str>) -> String {
    items.iter().map(|d| regex::escape(d)).collect::<Vec<_>>().join("|")
}

/// A task binding for string values: the task-context path most of them
/// equal, and an `or_pattern` for leftover email addresses that share a
/// domain (at least two distinct addresses).
struct Binding {
    path: String,
    matched: usize,
    or_pattern: Option<String>,
    or_covered: usize,
    /// Indices into the values that neither match nor are covered.
    leftovers: Vec<usize>,
}

fn bind(ctx: &Ctx, values: &[(usize, &Value)]) -> Option<Binding> {
    let n = values.len();
    let leaves: Vec<BTreeMap<String, BTreeSet<String>>> = ctx.sessions.iter().map(|s| task_leaves(s.task.as_ref())).collect();
    let paths: BTreeSet<&String> = leaves.iter().flat_map(BTreeMap::keys).collect();
    let hits = |path: &str| -> Vec<bool> {
        values.iter().map(|(s, v)| key(v).is_some_and(|k| leaves[*s].get(path).is_some_and(|set| set.contains(&k)))).collect()
    };
    let arg_tokens = tokens(ctx.path.rsplit('.').next().unwrap_or(&ctx.path));
    let (path, matches) = paths
        .into_iter()
        .map(|p| (p.clone(), hits(p)))
        .max_by_key(|(p, m)| (m.iter().filter(|x| **x).count(), overlap(&arg_tokens, p), std::cmp::Reverse(p.len())))?;
    let matched = matches.iter().filter(|x| **x).count();
    let low = n < ctx.opts.min_support;
    if matched == 0 || (low && matched < n) {
        return None;
    }
    // Leftover addresses that recur in one domain become an or_pattern.
    let mut domains: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (i, (_, v)) in values.iter().enumerate() {
        if let (false, Some(s)) = (matches[i], v.as_str()) {
            if let Some((local, domain)) = s.rsplit_once('@').filter(|_| super::load::classify(s) == "email") {
                domains.entry(domain.to_ascii_lowercase()).or_default().insert(local.to_string());
            }
        }
    }
    let ours: BTreeSet<String> = domains.into_iter().filter(|(_, locals)| locals.len() >= 2).map(|(d, _)| d).collect();
    let in_ours = |v: &Value| v.as_str().and_then(|s| s.rsplit_once('@')).is_some_and(|(_, d)| ours.contains(&d.to_ascii_lowercase()));
    let mut or_covered = 0;
    let mut leftovers = Vec::new();
    for (i, (_, v)) in values.iter().enumerate() {
        if matches[i] {
            continue;
        }
        if in_ours(v) {
            or_covered += 1;
        } else {
            leftovers.push(i);
        }
    }
    let rate = matched as f64 / (n - or_covered).max(1) as f64;
    if rate < ctx.opts.bind_threshold {
        return None;
    }
    let or_pattern = (!ours.is_empty()).then(|| {
        let set: BTreeSet<&str> = ours.iter().map(String::as_str).collect();
        if set.len() == 1 { format!("@{}$", alternation(&set)) } else { format!("@({})$", alternation(&set)) }
    });
    Some(Binding { path, matched, or_pattern, or_covered, leftovers })
}

/// Calls (indices into the tool's calls) whose value of `arg` is an outlier.
fn find_outliers(arg: &str, values: &[(usize, usize, &Value)], sessions: &[Session], opts: &Options) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let ctx = Ctx { tool: "", path: arg.to_string(), sessions, opts, calls: values.len() };
    let plain: Vec<(usize, &Value)> = values.iter().map(|(_, s, v)| (*s, *v)).collect();
    if values.iter().all(|(_, _, v)| v.is_string() || shape_of(v).is_some()) {
        if let Some(b) = bind(&ctx, &plain) {
            for i in b.leftovers {
                let why = format!("{arg} = {} is not task.{} and not a recurring domain", redact::example(values[i].2), b.path);
                out.push((values[i].0, why));
            }
        }
        let lens: Vec<f64> = values.iter().map(|(_, _, v)| str_len(v) as f64).collect();
        let median = median(&lens);
        for (i, len) in lens.iter().enumerate() {
            if *len > 100.0 && *len > 10.0 * median.max(1.0) {
                out.push((values[i].0, format!("{arg} is {len} characters, the median is {median}")));
            }
        }
    }
    let nums: Vec<f64> = values.iter().filter_map(|(_, _, v)| v.as_f64()).collect();
    if nums.len() == values.len() && !nums.is_empty() {
        let median = median(&nums.iter().map(|x| x.abs()).collect::<Vec<_>>());
        for (i, x) in nums.iter().enumerate() {
            if x.abs() > 10.0 * median.max(1.0) {
                out.push((values[i].0, format!("{arg} = {} is over ten times the median ({})", fmt_num(*x), fmt_num(median))));
            }
        }
    }
    out
}

/// The JSON type all values share (`integer` when every number is whole).
fn unify<'a>(values: impl Iterator<Item = &'a Value>) -> Option<&'static str> {
    let mut seen = BTreeSet::new();
    for v in values {
        seen.insert(match v {
            Value::String(_) => "string",
            v if shape_of(v).is_some() => "string",
            Value::Number(n) if n.is_i64() || n.is_u64() => "integer",
            Value::Number(_) => "number",
            Value::Bool(_) => "boolean",
            Value::Object(_) => "object",
            Value::Array(_) => "array",
            Value::Null => return None,
        });
    }
    if seen.len() == 2 && seen.contains("integer") && seen.contains("number") {
        return Some("number");
    }
    (seen.len() == 1).then(|| *seen.iter().next().unwrap())
}

/// Every string leaf of a task context by dotted path, keyed as [`key`] keys
/// values (arrays of strings: each element under the array's path).
pub fn task_leaves(task: Option<&Value>) -> BTreeMap<String, BTreeSet<String>> {
    fn walk(v: &Value, path: &str, out: &mut BTreeMap<String, BTreeSet<String>>) {
        if let Some(k) = key(v) {
            out.entry(path.to_string()).or_default().insert(k);
            return;
        }
        match v {
            Value::Object(o) => {
                for (k, x) in o {
                    let p = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    walk(x, &p, out);
                }
            }
            Value::Array(a) if !path.is_empty() => {
                for x in a {
                    if let Some(k) = key(x) {
                        out.entry(path.to_string()).or_default().insert(k);
                    }
                }
            }
            _ => {}
        }
    }
    let mut out = BTreeMap::new();
    if let Some(t) = task {
        walk(t, "", &mut out);
    }
    out
}

/// What equality compares: a raw string, or a shape's salted hash.
pub fn key(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(format!("s:{s}")),
        v => shape_of(v).and_then(|s| s.get("h")?.as_str().map(|h| format!("h:{h}"))),
    }
}

pub fn str_len(v: &Value) -> usize {
    match v {
        Value::String(s) => s.chars().count(),
        v => shape_of(v).and_then(|s| s.get("len")?.as_u64()).unwrap_or(0) as usize,
    }
}

fn class_of(v: &Value) -> String {
    match v {
        Value::String(s) => super::load::classify(s).to_string(),
        v => shape_of(v).and_then(|s| s.get("class")?.as_str().map(str::to_string)).unwrap_or_default(),
    }
}

fn id_prefix(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(cloakpipe_mcp::capture::id_prefix(s).to_string()).filter(|p| !p.is_empty()),
        v => shape_of(v).and_then(|s| s.get("prefix")?.as_str().map(str::to_string)),
    }
}

fn tokens(s: &str) -> BTreeSet<String> {
    s.split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).map(str::to_ascii_lowercase).collect()
}

fn overlap(a: &BTreeSet<String>, path: &str) -> usize {
    tokens(path).intersection(a).count()
}

fn median(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    let mut v = xs.to_vec();
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// `x` rounded up to `sig` significant digits (`3921` → `4000`, `120` → `120`).
pub fn nice_ceil(x: f64, sig: i32) -> f64 {
    if x.is_nan() || x <= 0.0 {
        return 0.0;
    }
    if !x.is_finite() {
        return x;
    }
    let step = 10f64.powi(x.log10().floor() as i32 - sig + 1);
    (x / step - 1e-9).ceil() * step
}

/// A bound as a JSON number; `None` (no bound, the type still holds) when
/// it does not fit: never one that would refuse an observed value.
fn number(x: f64, integer: bool) -> Option<Number> {
    if !x.is_finite() {
        return None;
    }
    if integer {
        (x.abs() < 9.0e18).then(|| Number::from(x.round() as i64))
    } else {
        Number::from_f64(x)
    }
}

pub fn fmt_num(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e15 { format!("{}", x as i64) } else { format!("{x}") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infer::load::{Call, Session};
    use serde_json::json;

    fn session(task: Value, calls: Vec<(&str, Value)>) -> Session {
        Session {
            task: Some(task),
            shapes: false,
            calls: calls.into_iter().map(|(t, a)| Call { tool: t.into(), args: Some(a) }).collect(),
            offered: BTreeMap::new(),
            forged: 0,
        }
    }

    #[test]
    fn nice_numbers() {
        assert_eq!(nice_ceil(3921.5, 1), 4000.0);
        assert_eq!(nice_ceil(120.0, 2), 120.0);
        assert_eq!(nice_ceil(96.0 * 1.25, 2), 120.0);
        assert_eq!(nice_ceil(96.0, 1), 100.0);
        assert_eq!(nice_ceil(12.65, 1), 20.0);
    }

    #[test]
    fn binds_recipient_to_the_task_with_an_internal_domain_and_drops_the_attack() {
        let mut sessions = Vec::new();
        for i in 0..8 {
            let email = format!("c{i}@customer{i}.example");
            let task = json!({ "taskId": format!("t-{i}"), "ticket": { "id": format!("T-10{i:02}"), "customer_email": email } });
            let mut calls = vec![("send_email", json!({ "ticket_id": format!("T-10{i:02}"), "to": email, "body": format!("Your refund {i} is on its way.") }))];
            if i % 3 == 0 {
                calls.push(("send_email", json!({ "ticket_id": format!("T-10{i:02}"), "to": format!("agent{i}@ourcompany.com"), "body": format!("FYI {i}") })));
            }
            if i == 5 {
                calls.push(("send_email", json!({ "ticket_id": "T-1005", "to": "attacker@evil.example", "body": "x".repeat(4000) })));
            }
            sessions.push(session(task, calls));
        }
        let draft = infer(&sessions, &Options::default());
        let tool = &draft.tools[0];
        assert_eq!(tool.excluded, 1, "{:?}", draft.review);
        let to = &tool.args["to"].spec;
        assert_eq!(to.one_of_context, vec!["ticket.customer_email".to_string()]);
        assert_eq!(to.or_pattern.as_deref(), Some("@ourcompany\\.com$"));
        assert_eq!(tool.args["ticket_id"].spec.one_of_context, vec!["ticket.id".to_string()]);
        // The 4000-character attack body did not widen the rule.
        assert!(tool.args["body"].spec.max_len.unwrap() < 100, "{:?}", tool.args["body"]);
        assert!(draft.review.iter().any(|r| r.contains("outlier excluded")));
        assert!(tool.side_effect);
    }

    #[test]
    fn ranges_enums_patterns_and_suggested_approvals() {
        let calls: Vec<(&str, Value)> = (0..10)
            .map(|i| ("issue_refund", json!({ "ticket_id": format!("T-{}", 1000 + i), "amount": 10 + i * 9, "reason": (["damaged", "late"][i as usize % 2]) })))
            .collect();
        let draft = infer(&[session(json!({}), calls)], &Options::default());
        let t = &draft.tools[0];
        assert_eq!(t.args["amount"].spec.ty, Some("integer"));
        assert_eq!(t.args["amount"].spec.min, Some(Number::from(0)));
        assert_eq!(t.args["amount"].spec.max, Some(Number::from(120)));
        assert_eq!(t.args["reason"].spec.one_of, Some(vec![json!("damaged"), json!("late")]));
        assert_eq!(t.args["ticket_id"].spec.pattern.as_deref(), Some("T\\-[0-9]{4,}"));
        assert_eq!(t.approval.as_deref(), Some("amount > 100"));
        assert!(t.args.values().all(|a| a.required));
        // Top 120: max 150, so the approval is 120, not 200 (which could never fire).
        let calls: Vec<(&str, Value)> = (1..=12).map(|i| ("issue_refund", json!({ "amount": 10 * i }))).collect();
        let t = &infer(&[session(json!({}), calls)], &Options::default()).tools[0];
        assert_eq!(t.args["amount"].spec.max, Some(Number::from(150)));
        assert_eq!(t.approval.as_deref(), Some("amount > 120"));
    }

    #[test]
    fn low_support_drafts_exact_bounds_only() {
        let draft = infer(&[session(json!({}), vec![("lookup", json!({ "q": "abc", "n": 7 }))])], &Options::default());
        let t = &draft.tools[0];
        assert_eq!(t.args["q"].spec.max_len, Some(3));
        assert_eq!(t.args["n"].spec.max, Some(Number::from(7)));
        assert!(draft.review[0].starts_with("low support"));
    }

    #[test]
    fn hostile_values_do_not_break_the_draft() {
        let calls: Vec<(&str, Value)> = (0..6)
            .map(|i| ("t", json!({ "id": format!("AB{}", i), "big": 1.0e308, "huge": u64::MAX, "e": format!("u{i}@x.example") })))
            .collect();
        let d = infer(&[session(json!({}), calls)], &Options::default());
        let a = &d.tools[0].args;
        assert!(a["big"].spec.max.as_ref().and_then(Number::as_f64).is_none_or(|m| m >= 1.0e308), "no bound that refuses what was seen");
        assert_eq!(a["huge"].spec.max, None);
        assert_eq!(a["e"].spec.one_of, None, "never an enum of addresses");
    }

    #[test]
    fn never_called_tools_are_listed_not_declared() {
        let mut s = session(json!({}), vec![("read", json!({}))]);
        s.offered.insert("export_customers".into(), Value::Null);
        s.offered.insert("read".into(), Value::Null);
        let draft = infer(&[s], &Options::default());
        assert_eq!(draft.undeclared, vec!["export_customers".to_string()]);
    }
}
