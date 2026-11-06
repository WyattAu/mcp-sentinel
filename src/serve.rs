//! `mcp-sentinel serve` — the sentinel as an MCP server (stdio, line-JSON).
//!
//! Exposes the integrity workflow as MCP tools so agents can call it
//! directly from their harness: scan a config root, pin a server's
//! tools/list hash, verify for drift, audit the chain.
//!
//! Protocol: JSON-RPC 2.0, one request per line (same framing as the
//! estate's standards server and aileron's TCP transport). stdout is the
//! protocol channel; diagnostics go to stderr.

use serde_json::{json, Value};
use sha2::Digest;
use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::{scan, store, CHAIN_DEFAULT};

fn tools_list() -> Value {
    json!({
        "tools": [
            {
                "name": "sentinel_scan",
                "description": "Scan a directory for MCP config files; evaluates IoC rules (remote servers, inline secrets, suspicious commands) and lists servers.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "root": { "type": "string", "description": "Directory to scan for MCP configs" } },
                    "required": ["root"]
                }
            },
            {
                "name": "sentinel_pin",
                "description": "Probe a server's tools/list and pin the hash into the tamper-evident chain.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config": { "type": "string", "description": "Path to the MCP config file" },
                        "server": { "type": "string", "description": "Server name in that config" }
                    },
                    "required": ["config", "server"]
                }
            },
            {
                "name": "sentinel_verify",
                "description": "Re-probe a server and compare its tools/list hash against the pin; detects tool-definition drift.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "config": { "type": "string" },
                        "server": { "type": "string" }
                    },
                    "required": ["config", "server"]
                }
            },
            {
                "name": "sentinel_verify_chain",
                "description": "Verify the hash chain of the sentinel audit log (tamper evidence).",
                "inputSchema": {
                    "type": "object",
                    "properties": { "chain": { "type": "string", "description": "Optional chain file; default .mcp-sentinel/chain.json" } }
                }
            }
        ]
    })
}

fn call_tool(name: &str, a: &Value) -> Result<Value, String> {
    match name {
        "sentinel_scan" => {
            let root = a
                .get("root")
                .and_then(|v| v.as_str())
                .ok_or("missing `root`")?;
            let report = scan::scan(&PathBuf::from(root), 6);
            let critical = report
                .findings
                .iter()
                .filter(|f| f.severity == "CRITICAL")
                .count();
            let warn = report.findings.iter().filter(|f| f.severity == "WARN").count();
            Ok(json!({
                "ok": critical == 0,
                "root": root,
                "files_scanned": report.files_scanned,
                "servers": report.servers,
                "critical": critical,
                "warn": warn,
                "findings": report.findings,
                "servers_listed": report.servers_listed,
            }))
        }
        "sentinel_pin" | "sentinel_verify" => {
            let config = a.get("config").and_then(|v| v.as_str()).ok_or("missing `config`")?;
            let server = a.get("server").and_then(|v| v.as_str()).ok_or("missing `server`")?;
            let target = crate::parse_target(&[
                "x".into(),
                "--config".into(),
                config.into(),
                "--server".into(),
                server.into(),
            ])?;
            let server_name = match &target {
                crate::Target::Stdio { server, .. } => server.clone(),
                crate::Target::Remote { url, .. } => url.clone(),
            };
            let chain_path = std::env::var("AILERON_SENTINEL_CHAIN")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(CHAIN_DEFAULT));
            let tools = crate::probe_target(&target)?;
            let canonical = serde_json::to_string(&tools).unwrap_or_default();
            let mut h = sha2::Sha256::new();
            h.update(canonical.as_bytes());
            let hash = format!("{:x}", h.finalize());
            let tools_count = tools
                .get("tools")
                .and_then(|t| t.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            if name == "sentinel_pin" {
                let mut chain = store::load(&chain_path)?;
                let previous = chain
                    .entries
                    .last()
                    .map(|e| e.hash.clone())
                    .unwrap_or_else(|| "0".repeat(64));
                let entry = tamper_audit::AuditEntry::new(
                    "mcp-sentinel",
                    "pin-tools",
                    &server_name,
                    json!({ "tools_hash": hash, "tools_count": tools_count, "target": server_name }),
                    &previous,
                );
                chain.entries.push(entry);
                store::save(&chain_path, &chain)?;
                Ok(json!({
                    "ok": true, "server": server_name, "tools_hash": hash,
                    "tools_count": tools_count, "chain_index": chain.entries.len() - 1,
                    "pinned": true,
                }))
            } else {
                let chain = store::load(&chain_path)?;
                let pinned = chain
                    .entries
                    .iter()
                    .rev()
                    .find(|e| e.action == "pin-tools" && e.resource == server_name)
                    .and_then(|e| e.details.get("tools_hash").and_then(|h| h.as_str()).map(String::from));
                let Some(pinned_hash) = pinned else {
                    return Err("no pinned snapshot for this server; run sentinel_pin first".into());
                };
                let drift = hash != *pinned_hash;
                Ok(json!({
                    "ok": !drift, "server": server_name,
                    "pinned_hash": pinned_hash, "current_hash": hash,
                    "drift": drift,
                    "verdict": if drift { "TOOL DEFINITIONS CHANGED since pin; re-approve before trusting this server" } else { "tool definitions match pin" },
                }))
            }
        }
        "sentinel_verify_chain" => {
            let chain_path = a
                .get("chain")
                .and_then(|v| v.as_str())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(CHAIN_DEFAULT));
            let chain = store::load(&chain_path)?;
            let result = tamper_audit::AuditChain::verify(&chain.entries);
            Ok(json!({
                "ok": result.is_valid(),
                "total_entries": result.total_entries,
                "valid_entries": result.valid_entries,
                "broken_at": result.broken_at,
                "error": result.error,
            }))
        }
        other => Err(format!("unknown tool `{other}`")),
    }
}

fn reply(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_reply(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

pub fn cmd_serve(_args: &[String]) -> i32 {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
        let id = v.get("id").cloned().unwrap_or(Value::Null);
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let resp = match method {
            "initialize" => reply(
                &id,
                json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "mcp-sentinel", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "ping" => reply(&id, json!({})),
            "tools/list" => reply(&id, tools_list()),
            "tools/call" => {
                let params = v.get("params").cloned().unwrap_or(json!({}));
                let name = params
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
                match call_tool(&name, &arguments) {
                    Ok(result) => reply(
                        &id,
                        json!({
                            "content": [{ "type": "text", "text": serde_json::to_string(&result).unwrap_or_default() }],
                            "isError": false
                        }),
                    ),
                    Err(e) => reply(
                        &id,
                        json!({
                            "content": [{ "type": "text", "text": e.clone() }],
                            "isError": true
                        }),
                    ),
                }
            }
            m if m.starts_with("notifications/") => continue,
            other => error_reply(&id, -32601, &format!("method not found: {other}")),
        };
        let mut line_out = serde_json::to_string(&resp).unwrap_or_default();
        line_out.push('\n');
        if out.write_all(line_out.as_bytes()).is_err() {
            break;
        }
        let _ = out.flush();
    }
    0
}
