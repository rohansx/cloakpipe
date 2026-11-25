//! Reading capture files (`mcp-proxy --capture`) into sessions.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub use cloakpipe_mcp::capture::classify;
use cloakpipe_mcp::capture::{CAPTURE_VERSION, SHAPE_KEY};

/// One proxy run: its task context, the calls the agent made and the tools
/// it was offered.
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub task: Option<Value>,
    /// Strings were captured as shapes only.
    pub shapes: bool,
    pub calls: Vec<Call>,
    /// Tool name -> input schema, from `tools/list` replies.
    pub offered: BTreeMap<String, Value>,
    /// Calls left out because an argument posed as a shape in a session
    /// captured with raw values (only an agent could have sent it).
    pub forged: usize,
}

#[derive(Debug, Clone)]
pub struct Call {
    pub tool: String,
    pub args: Option<Value>,
}

/// A shaped string's shape (`{"$shape": {…}}`), if `v` is one.
pub fn shape_of(v: &Value) -> Option<&Value> {
    let o = v.as_object()?;
    (o.len() == 1).then(|| o.get(SHAPE_KEY)).flatten()
}

fn has_shape(v: &Value) -> bool {
    shape_of(v).is_some()
        || match v {
            Value::Array(a) => a.iter().any(has_shape),
            Value::Object(o) => o.values().any(has_shape),
            _ => false,
        }
}

/// The capture files under `inputs`: each a file, or a directory of
/// `capture-*.jsonl`.
pub fn capture_files(inputs: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for p in inputs {
        if p.is_dir() {
            out.extend(cloakpipe_mcp::capture::files(p).map_err(|e| format!("{}: {e}", p.display()))?);
        } else if p.is_file() {
            out.push(p.clone());
        } else {
            return Err(format!("{}: no such file or directory", p.display()));
        }
    }
    if out.is_empty() {
        return Err("no capture files found (run mcp-proxy with --capture <dir> first)".into());
    }
    Ok(out)
}

/// The sessions in one file: a CloakPipe capture, or OpenTelemetry traces
/// (OTLP/JSON), one session per trace.
pub fn read_all(path: &Path) -> Result<Vec<Session>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if super::otel::is_otlp(&text) {
        return super::otel::read(&text).map_err(|e| format!("{}: {e}", path.display()));
    }
    read(path).map(|s| vec![s])
}

/// Read one capture file. Unknown record kinds are skipped; a malformed line
/// is an error (with its line number).
pub fn read(path: &Path) -> Result<Session, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut session = Session::default();
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let at = || format!("{}:{}", path.display(), i + 1);
        let rec: Value = serde_json::from_str(line).map_err(|e| format!("{}: not JSON: {e}", at()))?;
        if rec.get("v").and_then(Value::as_u64) != Some(CAPTURE_VERSION) {
            return Err(format!("{}: unsupported capture version", at()));
        }
        match rec.get("kind").and_then(Value::as_str) {
            Some("session") => {
                session.shapes = rec.get("shapes").and_then(Value::as_bool).unwrap_or(false);
                session.task = rec.get("task").filter(|t| t.is_object()).cloned();
            }
            Some("call") => {
                let tool = rec.get("tool").and_then(Value::as_str).ok_or_else(|| format!("{}: call without a tool", at()))?;
                let args = rec.get("args").filter(|a| !a.is_null()).cloned();
                if !session.shapes && args.as_ref().is_some_and(has_shape) {
                    session.forged += 1;
                    continue;
                }
                session.calls.push(Call { tool: tool.to_string(), args });
            }
            Some("tools") => {
                for t in rec.get("tools").and_then(Value::as_array).into_iter().flatten() {
                    if let Some(name) = t.get("name").and_then(Value::as_str) {
                        session.offered.insert(name.to_string(), t.get("inputSchema").cloned().unwrap_or(Value::Null));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(session)
}
