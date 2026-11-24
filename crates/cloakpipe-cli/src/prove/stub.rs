//! `cloakpipe prove-stub`: the stub MCP tool server a `prove` run puts
//! behind the gate. It answers `initialize`, `tools/list` and `tools/call`
//! on stdio, and appends every call that reached it to a JSONL log (`{"tool",
//! "args"}`): the ground truth of what got past the gate.

use clap::Args;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;

use super::pack::{StubBehaviour, StubTool};

#[derive(Debug, Args)]
pub struct StubArgs {
    /// The stub's configuration (written by `prove`)
    #[arg(long)]
    pub config: PathBuf,
    /// Where each call that reached a tool is appended
    #[arg(long)]
    pub log: PathBuf,
}

/// What `prove` writes for the stub.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct StubConfig {
    pub tools: Vec<StubTool>,
    pub ticket: String,
    #[serde(default)]
    pub behaviour: StubBehaviour,
}

pub fn run(a: StubArgs) -> i32 {
    match serve(&a) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("prove-stub: {e}");
            2
        }
    }
}

fn serve(a: &StubArgs) -> Result<(), String> {
    let config: StubConfig = serde_json::from_str(&std::fs::read_to_string(&a.config).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(&a.log).map_err(|e| e.to_string())?;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        let Some(id) = msg.get("id").filter(|id| !id.is_null()).cloned() else { continue };
        let result = match msg.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "protocolVersion": msg.pointer("/params/protocolVersion").cloned().unwrap_or(json!("2025-06-18")),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "cloakpipe-prove-stub", "version": env!("CARGO_PKG_VERSION") },
            }),
            Some("tools/list") => json!({ "tools": config.tools.iter().map(|t| json!({
                "name": t.name, "description": t.description, "inputSchema": t.input_schema,
            })).collect::<Vec<_>>() }),
            Some("tools/call") => {
                let tool = msg.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
                let args = msg.pointer("/params/arguments").cloned().unwrap_or(Value::Null);
                writeln!(log, "{}", json!({ "tool": tool, "args": args })).map_err(|e| e.to_string())?;
                log.flush().map_err(|e| e.to_string())?;
                if config.behaviour.hang_after.iter().any(|t| t == tool) {
                    // The effect happened; the answer never comes (a timeout).
                    continue;
                }
                match config.tools.iter().find(|t| t.name == tool) {
                    Some(t) => json!({ "content": [{ "type": "text", "text": t.reply.replace("{ticket}", &config.ticket) }] }),
                    None => {
                        let err = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": format!("unknown tool {tool}") } });
                        writeln!(out, "{err}").map_err(|e| e.to_string())?;
                        out.flush().map_err(|e| e.to_string())?;
                        continue;
                    }
                }
            }
            Some("ping") => json!({}),
            _ => {
                let err = json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32601, "message": "method not found" } });
                writeln!(out, "{err}").map_err(|e| e.to_string())?;
                out.flush().map_err(|e| e.to_string())?;
                continue;
            }
        };
        writeln!(out, "{}", json!({ "jsonrpc": "2.0", "id": id, "result": result })).map_err(|e| e.to_string())?;
        out.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}
