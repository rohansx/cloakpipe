//! Redacted examples for the draft's comments: enough to recognise a value,
//! never the whole of a sensitive one.

use serde_json::Value;

use super::load::{classify, shape_of};

/// One value as a short redacted example.
pub fn example(v: &Value) -> String {
    match v {
        Value::String(s) => string(s),
        Value::Number(_) | Value::Bool(_) | Value::Null => v.to_string(),
        v if shape_of(v).is_some() => {
            let s = shape_of(v).unwrap_or(&Value::Null);
            let class = s.get("class").and_then(Value::as_str).unwrap_or("?");
            format!("<{class}, {} chars>", s.get("len").and_then(Value::as_u64).unwrap_or(0))
        }
        Value::Array(a) => format!("<array, {} items>", a.len()),
        Value::Object(o) => format!("<object, {} members>", o.len()),
    }
}

fn string(s: &str) -> String {
    let n = s.chars().count();
    match classify(s) {
        "email" => {
            let (local, domain) = s.split_once('@').unwrap_or((s, ""));
            format!("{}***@{domain}", local.chars().next().unwrap_or('?'))
        }
        // An id keeps its prefix and half its digits (`T-1***`); bare digits
        // (card numbers, phone numbers) and UUIDs keep none.
        "id" => {
            let keep = n.div_ceil(2).min(8);
            format!("{}{}", s.chars().take(keep).collect::<String>(), "*".repeat(n - keep))
        }
        "url" => {
            let host = s.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("");
            format!("{}://{host}/…", s.split("://").next().unwrap_or("https"))
        }
        class => format!("<{class}, {n} chars>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn examples_hide_values() {
        assert_eq!(example(&json!("dana@customer.example")), "d***@customer.example");
        assert_eq!(example(&json!("T-1042")), "T-1***");
        assert_eq!(example(&json!("Your refund is on its way")), "<text, 25 chars>");
        assert_eq!(example(&json!(96)), "96");
    }
}
