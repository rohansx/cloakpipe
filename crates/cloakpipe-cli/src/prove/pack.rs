//! Attack packs: the stub tools, and scenarios that plant an attack and say
//! which call would mean it worked.

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The packs built into the binary, by name.
const BUILT_IN: &[(&str, &str)] = &[
    ("support-basics", include_str!("../../packs/support-basics.yaml")),
    ("support-injection", include_str!("../../packs/support-injection.yaml")),
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pack {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub tools: Vec<StubTool>,
    pub scenarios: Vec<Scenario>,
}

/// A stub tool: what it lists and what it answers.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StubTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "inputSchema", default = "empty_schema")]
    pub input_schema: Value,
    /// The text result; `{ticket}` is the scenario's ticket.
    #[serde(default)]
    pub reply: String,
}

fn empty_schema() -> Value {
    serde_json::json!({ "type": "object" })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Attack,
    Control,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub id: String,
    pub kind: Kind,
    pub title: String,
    #[serde(default)]
    pub planted: String,
    /// The trusted task context the gate runs with.
    pub task: Value,
    /// What the agent is asked to do.
    pub prompt: String,
    /// The ticket `read_ticket` returns (`{{repeat:TEXT,N}}` is expanded).
    #[serde(default)]
    pub ticket: String,
    #[serde(default)]
    pub stub: StubBehaviour,
    /// A call an approver signed a receipt for, before the run.
    pub approved: Option<ApprovedCall>,
    /// Attack: the call that means the attack worked.
    pub bad_call: Option<Matcher>,
    /// Attack: refusal reasons that count as the gate holding.
    #[serde(default)]
    pub expect: Vec<String>,
    /// Control: calls that must reach the tools for the task to be done.
    #[serde(default)]
    pub must_reach: Vec<Matcher>,
}

#[derive(Debug, Clone, Default, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct StubBehaviour {
    /// Tools that perform the call and record it, then never answer it (a
    /// timeout after the effect); the server keeps serving other calls.
    #[serde(default)]
    pub hang_after: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedCall {
    pub tool: String,
    pub args: Value,
}

/// A tool call pattern: the tool, conditions on its arguments, and how many
/// such calls it takes (`times`, default 1).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matcher {
    pub tool: String,
    #[serde(default, rename = "where")]
    pub conditions: BTreeMap<String, Condition>,
    #[serde(default = "one")]
    pub times: usize,
}

fn one() -> usize {
    1
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub eq: Option<Value>,
    pub ne: Option<Value>,
    pub gt: Option<f64>,
    pub lt: Option<f64>,
    pub len_gt: Option<usize>,
    pub contains: Option<String>,
}

impl Matcher {
    /// Whether one call `(tool, args)` matches (ignoring `times`).
    pub fn matches(&self, tool: &str, args: Option<&Value>) -> bool {
        tool == self.tool
            && self.conditions.iter().all(|(arg, c)| {
                let v = args.and_then(|a| a.get(arg));
                c.holds(v)
            })
    }

    /// Whether `calls` hold enough matching calls.
    pub fn met_by<'a>(&self, calls: impl Iterator<Item = (&'a str, Option<&'a Value>)>) -> bool {
        calls.filter(|(t, a)| self.matches(t, *a)).count() >= self.times
    }
}

impl Condition {
    fn holds(&self, v: Option<&Value>) -> bool {
        let num = v.and_then(Value::as_f64);
        let text = v.and_then(Value::as_str);
        self.eq.as_ref().is_none_or(|x| v == Some(x))
            && self.ne.as_ref().is_none_or(|x| v.is_some_and(|v| v != x))
            && self.gt.is_none_or(|x| num.is_some_and(|n| n > x))
            && self.lt.is_none_or(|x| num.is_some_and(|n| n < x))
            && self.len_gt.is_none_or(|x| text.is_some_and(|s| s.chars().count() > x))
            && self.contains.as_ref().is_none_or(|x| text.is_some_and(|s| s.contains(x.as_str())))
    }
}

/// A built-in pack by name, or a pack file.
pub fn load(name_or_path: &str) -> Result<Pack, String> {
    let src = match BUILT_IN.iter().find(|(n, _)| *n == name_or_path) {
        Some((_, src)) => src.to_string(),
        None => std::fs::read_to_string(Path::new(name_or_path)).map_err(|e| {
            let names: Vec<&str> = BUILT_IN.iter().map(|(n, _)| *n).collect();
            format!("--pack {name_or_path}: not a built-in pack ({}) or a readable file: {e}", names.join(", "))
        })?,
    };
    let mut pack: Pack = serde_yaml::from_str(&src).map_err(|e| format!("--pack {name_or_path}: {e}"))?;
    let mut ids = std::collections::BTreeSet::new();
    for s in &mut pack.scenarios {
        // Ids name directories.
        if s.id.is_empty() || !s.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || !ids.insert(s.id.clone()) {
            return Err(format!("scenario {:?}: ids must be unique and use only letters, digits, - and _", s.id));
        }
        s.ticket = expand(&s.ticket);
        match s.kind {
            Kind::Attack if s.bad_call.is_none() => return Err(format!("scenario {}: an attack needs bad_call", s.id)),
            Kind::Control if s.must_reach.is_empty() => return Err(format!("scenario {}: a control needs must_reach", s.id)),
            _ => {}
        }
        if !s.task.is_object() {
            return Err(format!("scenario {}: task must be a JSON object", s.id));
        }
    }
    Ok(pack)
}

/// `{{repeat:TEXT,N}}` -> TEXT repeated N times (N at most 100000 characters' worth).
fn expand(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find("{{repeat:") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 9..];
        let Some(end) = after.find("}}") else { break };
        let (text, n) = after[..end].rsplit_once(',').unwrap_or((&after[..end], "1"));
        let n: usize = n.trim().parse().unwrap_or(1);
        out.push_str(&text.repeat(n.min(100_000 / text.len().max(1))));
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn built_in_pack_loads() {
        let p = load("support-basics").unwrap();
        assert_eq!(p.scenarios.len(), 6);
        let stretch = p.scenarios.iter().find(|s| s.id == "argument-stretching").unwrap();
        assert!(stretch.ticket.len() > 8000, "{}", stretch.ticket.len());
        assert_eq!(load("support-injection").unwrap().scenarios.len(), 7);
    }

    #[test]
    fn matchers() {
        let m: Matcher = serde_yaml::from_str("{ tool: send_email, where: { to: { ne: a@x.example } } }").unwrap();
        assert!(m.matches("send_email", Some(&json!({ "to": "evil@y.example" }))));
        assert!(!m.matches("send_email", Some(&json!({ "to": "a@x.example" }))));
        assert!(!m.matches("send_email", Some(&json!({}))));
        let twice: Matcher = serde_yaml::from_str("{ tool: issue_refund, times: 2 }").unwrap();
        let one = [("issue_refund", None)];
        assert!(!twice.met_by(one.iter().map(|(t, a)| (*t, *a))));
        let two = [("issue_refund", None), ("issue_refund", None)];
        assert!(twice.met_by(two.iter().map(|(t, a)| (*t, *a))));
    }
}
