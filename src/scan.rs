//! MCP config discovery + parsing + server entry classification.

use crate::ioc;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

const CONFIG_NAMES: &[&str] = &[
    "opencode.json",
    "opencode.jsonc",
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    ".cursor.json",
];

#[derive(Serialize, Clone)]
pub struct ServerEntry {
    pub file: String,
    pub name: String,
    pub kind: String, // remote | local | unknown
    pub blob: String, // canonical JSON of the server entry (rules match here)
}

#[derive(Serialize)]
pub struct ScanReport {
    pub files_scanned: usize,
    pub servers: usize,
    pub findings: Vec<ioc::Finding>,
    pub servers_listed: Vec<ServerEntry>,
}

/// Strip // and /* */ comments (JSONC tolerance, mirrors opencode config).
fn strip_comments(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b: Vec<char> = s.chars().collect();
    let mut i = 0;
    let mut in_str = false;
    let mut in_line = false;
    let mut in_block = false;
    while i < b.len() {
        let c = b[i];
        let next = b.get(i + 1).copied();
        if in_line {
            if c == '\n' {
                in_line = false;
                out.push(c);
            }
            i += 1;
            continue;
        }
        if in_block {
            if c == '*' && next == Some('/') {
                in_block = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if in_str {
            out.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    out.push(n);
                    i += 1;
                }
            } else if c == '"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '/' && next == Some('/') {
            in_line = true;
            i += 1;
            continue;
        }
        if c == '/' && next == Some('*') {
            in_block = true;
            i += 2;
            continue;
        }
        out.push(c);
        i += 1;
    }
    out
}

fn looks_like_config(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    CONFIG_NAMES.iter().any(|n| name.ends_with(n))
}

fn extract_servers(file: &str, v: &Value) -> Vec<ServerEntry> {
    let mut out = Vec::new();
    // V2: mcp.servers { name: {type, url/command...} }
    // V1: mcp { name: {...} }  (flat)
    // Claude Desktop: mcpServers { name: {command|url...} }
    // Container precedence: first match wins. V2 = mcp.servers; V1 flat =
    // mcp.<server-name> directly. Without the break, a V2 config also yields
    // a bogus "servers" entry when /mcp is re-read as a flat map.
    let containers = [
        v.pointer("/mcp/servers"),
        v.pointer("/mcpServers"),
        v.pointer("/mcp"),
    ];
    for container in containers.into_iter().flatten() {
        let Some(map) = container.as_object() else { continue };
        for (name, entry) in map {
            if !entry.is_object() {
                continue;
            }
            let blob = serde_json::to_string(entry).unwrap_or_default();
            let kind = if blob.contains("\"url\"") {
                "remote"
            } else if blob.contains("\"command\"") {
                "local"
            } else {
                "unknown"
            };
            out.push(ServerEntry {
                file: file.to_string(),
                name: name.clone(),
                kind: kind.to_string(),
                blob,
            });
        }
        break;
    }
    out
}

pub fn discover_configs(root: &Path, max_depth: u8) -> Vec<PathBuf> {
    let mut found = Vec::new();
    fn walk(dir: &Path, depth: u8, max_depth: u8, found: &mut Vec<PathBuf>) {
        if depth > max_depth {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for e in entries.filter_map(|e| e.ok()) {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.starts_with('.') && depth > 0 && name != ".mcp.json" && name != ".claude.json" {
                // skip hidden dirs except the known config files themselves
                if p.is_dir() {
                    if matches!(name, "node_modules" | "target" | ".git" | "dist") {
                        continue;
                    }
                    walk(&p, depth + 1, max_depth, found);
                }
                continue;
            }
            if p.is_dir() {
                walk(&p, depth + 1, max_depth, found);
            } else if looks_like_config(&p) {
                found.push(p);
            }
        }
    }
    walk(root, 0, max_depth, &mut found);
    found
}

pub fn scan(root: &Path, max_depth: u8) -> ScanReport {
    let configs = discover_configs(root, max_depth);
    let mut servers_listed = Vec::new();
    let mut findings: Vec<ioc::Finding> = Vec::new();
    let mut scanned = 0usize;

    for path in &configs {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let cleaned = strip_comments(&raw);
        let Ok(v) = serde_json::from_str::<Value>(&cleaned) else { continue };
        scanned += 1;
        let file = path.display().to_string();
        for entry in extract_servers(&file, &v) {
            findings.extend(ioc::evaluate(&entry.name, &entry.kind, &entry.blob));
            servers_listed.push(entry);
        }
    }
    servers_listed.sort_by(|a, b| a.file.cmp(&b.file).then(a.name.cmp(&b.name)));
    ScanReport { files_scanned: scanned, servers: servers_listed.len(), findings, servers_listed }
}

pub fn load_server_config(config_path: &str, server: &str) -> Result<(String, Vec<String>), String> {
    let raw = std::fs::read_to_string(config_path).map_err(|e| e.to_string())?;
    let cleaned = strip_comments(&raw);
    let v: Value = serde_json::from_str(&cleaned).map_err(|e| format!("parse: {e}"))?;
    let entry = [v.pointer("/mcp/servers"), v.pointer("/mcpServers"), v.pointer("/mcp")]
        .into_iter()
        .flatten()
        .find_map(|c| c.get(server))
        .ok_or_else(|| format!("server `{server}` not found in {config_path}"))?;
    let command = entry
        .get("command")
        .and_then(|c| c.as_str())
        .ok_or_else(|| "only local stdio servers can be probed in v0.1".to_string())?
        .to_string();
    let args: Vec<String> = entry
        .get("args")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    Ok((command, args))
}

pub fn cmd_scan(args: &[String]) -> i32 {
    let as_json = args.iter().any(|a| a == "--json");
    let root = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    let report = scan(&root, 6);
    let critical = report.findings.iter().filter(|f| f.severity == "CRITICAL").count();
    let warn = report.findings.iter().filter(|f| f.severity == "WARN").count();
    let payload = serde_json::json!({
        "ok": critical == 0,
        "root": root.display().to_string(),
        "files_scanned": report.files_scanned,
        "servers": report.servers,
        "critical": critical,
        "warn": warn,
        "findings": report.findings,
        "servers_listed": report.servers_listed,
    });
    println!("{}", serde_json::to_string_pretty(&payload).unwrap_or_default());
    if critical > 0 { 1 } else { 0 }
}
