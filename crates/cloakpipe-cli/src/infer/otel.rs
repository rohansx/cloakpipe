//! OpenTelemetry traces as a capture source: OTLP/JSON (`{"resourceSpans": …}`,
//! one document or the collector file exporter's one per line). Each trace is a
//! session; each span with `gen_ai.tool.name` is a call, with its arguments
//! from `gen_ai.tool.call.arguments` (the GenAI semantic conventions; the
//! instrumentation must be set to record them). A span attribute
//! `cloakpipe.task` (the task context as JSON) gives the session its task.

use super::load::{Call, Session};
use serde_json::Value;
use std::collections::BTreeMap;

/// Whether `text` looks like OTLP/JSON rather than a CloakPipe capture.
pub fn is_otlp(text: &str) -> bool {
    let first = serde_json::from_str::<Value>(text).ok().or_else(|| text.lines().find(|l| !l.trim().is_empty()).and_then(|l| serde_json::from_str(l).ok()));
    first.is_some_and(|v| v.get("resourceSpans").is_some())
}

/// Sessions (one per trace) from an OTLP/JSON document or JSONL of them.
pub fn read(text: &str) -> Result<Vec<Session>, String> {
    let docs: Vec<Value> = match serde_json::from_str::<Value>(text) {
        Ok(doc) => vec![doc],
        Err(_) => text
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| serde_json::from_str(l).map_err(|e| format!("line {}: not JSON: {e}", i + 1)))
            .collect::<Result<_, _>>()?,
    };
    // trace id -> its (start time, call)s and its task.
    type Trace = (Vec<(u64, Call)>, Option<Value>);
    let mut traces: BTreeMap<String, Trace> = BTreeMap::new();
    let spans = docs.iter().flat_map(|d| list(d, "resourceSpans")).flat_map(|r| list(r, "scopeSpans")).flat_map(|s| list(s, "spans"));
    for span in spans {
        let attrs = attributes(span);
        let trace = traces.entry(span.get("traceId").and_then(Value::as_str).unwrap_or("").to_string()).or_default();
        if let Some(task) = attrs.get("cloakpipe.task").and_then(parse_json).filter(Value::is_object) {
            trace.1 = Some(task);
        }
        let Some(tool) = attrs.get("gen_ai.tool.name").and_then(Value::as_str) else { continue };
        let args = attrs.get("gen_ai.tool.call.arguments").and_then(parse_json).filter(|a| !a.is_null());
        let start = span.get("startTimeUnixNano").and_then(|t| t.as_str().and_then(|s| s.parse().ok()).or(t.as_u64())).unwrap_or(0);
        trace.0.push((start, Call { tool: tool.to_string(), args }));
    }
    Ok(traces
        .into_values()
        .filter(|(calls, _)| !calls.is_empty())
        .map(|(mut calls, task)| {
            calls.sort_by_key(|(t, _)| *t);
            Session { task, calls: calls.into_iter().map(|(_, c)| c).collect(), ..Session::default() }
        })
        .collect())
}

fn list<'a>(v: &'a Value, key: &str) -> impl Iterator<Item = &'a Value> {
    v.get(key).and_then(Value::as_array).into_iter().flatten()
}

/// OTLP attributes (`[{key, value: {stringValue | intValue | …}}]`) as JSON values.
fn attributes(span: &Value) -> BTreeMap<String, Value> {
    list(span, "attributes")
        .filter_map(|a| Some((a.get("key")?.as_str()?.to_string(), any_value(a.get("value")?))))
        .collect()
}

fn any_value(v: &Value) -> Value {
    let Some((kind, x)) = v.as_object().and_then(|o| o.iter().next()) else { return Value::Null };
    match kind.as_str() {
        // OTLP/JSON encodes 64-bit integers as strings.
        "intValue" => x.as_str().and_then(|s| s.parse::<i64>().ok()).map(Value::from).unwrap_or_else(|| x.clone()),
        "arrayValue" => Value::Array(list(x, "values").map(any_value).collect()),
        "kvlistValue" => Value::Object(list(x, "values").filter_map(|kv| Some((kv.get("key")?.as_str()?.to_string(), any_value(kv.get("value")?)))).collect()),
        _ => x.clone(),
    }
}

/// A JSON-encoded string attribute, or an already structured one.
fn parse_json(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => serde_json::from_str(s).ok(),
        other => Some(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn span(trace: &str, start: u64, attrs: Value) -> Value {
        json!({ "traceId": trace, "startTimeUnixNano": start.to_string(), "attributes": attrs })
    }
    fn s(k: &str, v: &str) -> Value {
        json!({ "key": k, "value": { "stringValue": v } })
    }

    #[test]
    fn traces_become_sessions_of_tool_calls() {
        let doc = json!({ "resourceSpans": [{ "scopeSpans": [{ "spans": [
            span("a", 2, json!([s("gen_ai.operation.name", "execute_tool"), s("gen_ai.tool.name", "issue_refund"), s("gen_ai.tool.call.arguments", r#"{"amount":40}"#)])),
            span("a", 1, json!([s("gen_ai.tool.name", "read_ticket"), s("cloakpipe.task", r#"{"ticket":{"id":"T-1"}}"#)])),
            span("a", 3, json!([s("gen_ai.operation.name", "chat")])),
            span("b", 1, json!([s("gen_ai.tool.name", "send_email"), json!({ "key": "gen_ai.tool.call.arguments", "value": { "kvlistValue": { "values": [{ "key": "n", "value": { "intValue": "7" } }] } } })])),
            span("c", 1, json!([s("gen_ai.operation.name", "chat")])),
        ]}]}]});
        let text = doc.to_string();
        assert!(is_otlp(&text));
        assert!(!is_otlp(r#"{"v":1,"kind":"session"}"#));
        let sessions = read(&text).unwrap();
        assert_eq!(sessions.len(), 2, "trace c has no tool calls");
        let a = &sessions[0];
        assert_eq!(a.calls.iter().map(|c| c.tool.as_str()).collect::<Vec<_>>(), ["read_ticket", "issue_refund"]);
        assert_eq!(a.calls[1].args, Some(json!({ "amount": 40 })));
        assert_eq!(a.task, Some(json!({ "ticket": { "id": "T-1" } })));
        assert_eq!(sessions[1].calls[0].args, Some(json!({ "n": 7 })));
        // The collector's file exporter: one document per line.
        assert_eq!(read(&format!("{text}\n{text}\n")).unwrap()[0].calls.len(), 4);
    }
}
