//! mcp-sentinel — MCP supply-chain integrity gate.
//!
//! The controls every 2026 incident advisory recommends, in one tool:
//!   scan    gitleaks-style PR/diff scanner for MCP config entries
//!           (Deadbugz IoCs + structural suspicion rules)
//!   pin     snapshot a server's tools/list into a tamper-evident chain
//!   verify  re-probe and compare against the pinned snapshot (catches
//!           Deadbugz-class mid-session tool-definition mutation)
//!   verify-chain  re-derive the tamper-audit chain
//!
//! Threat model and sources: docs/mcp-supply-chain-threat-model.md
//! Exit codes: 0 ok, 1 findings/verification failure, 2 usage/IO.

mod ioc;
mod mcp_client;
mod scan;
mod serve;
mod store;

use serde_json::{json, Value};
use sha2::Digest;
use std::path::PathBuf;
use std::time::Duration;

pub const CHAIN_DEFAULT: &str = ".mcp-sentinel/chain.json";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("scan") => scan::cmd_scan(&args[1..]),
        Some("serve") => serve::cmd_serve(&args[1..]),
        Some("pin") => cmd_pin(&args[1..]),
        Some("verify") => cmd_verify(&args[1..]),
        Some("verify-chain") => cmd_verify_chain(&args[1..]),
        Some("watch") => cmd_watch(&args[1..]),
        _ => {
            eprintln!(
                "usage: mcp-sentinel scan <path> [--json]\n       \
                 mcp-sentinel pin --config <file> --server <name> [--chain <file>]\n       \
                 mcp-sentinel verify --config <file> --server <name> [--chain <file>]\n       \
                 mcp-sentinel verify-chain [--chain <file>]\n       \
                 mcp-sentinel watch --config <file> --server <name> [--interval <secs>] [--chain <file>]"
            );
            2
        }
    };
    std::process::exit(code);
}

fn chain_path(args: &[String]) -> PathBuf {
    args.iter()
        .position(|a| a == "--chain")
        .and_then(|p| args.get(p + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(CHAIN_DEFAULT))
}

/// A probe target: local stdio server (config+name) or remote HTTP URL.
enum Target {
    Stdio { config: String, server: String },
    Remote { url: String, headers: Vec<(String, String)> },
}

pub fn parse_target(args: &[String]) -> Result<Target, String> {
    let get = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|p| args.get(p + 1)).cloned()
    };
    if let Some(url) = get("--url") {
        let mut headers = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if args[i] == "--header" {
                if let Some(hv) = args.get(i + 1) {
                    if let Some((k, v)) = hv.split_once(':') {
                        headers.push((k.trim().to_string(), v.trim().to_string()));
                    }
                    i += 1;
                }
            }
            i += 1;
        }
        return Ok(Target::Remote { url, headers });
    }
    let (Some(config), Some(server)) = (get("--config"), get("--server")) else {
        return Err("requires --config <file> --server <name> (stdio) or --url <endpoint> (remote)".into());
    };
    Ok(Target::Stdio { config, server })
}

pub fn probe_target(t: &Target) -> Result<Value, String> {
    match t {
        Target::Stdio { config, server } => mcp_client::probe_tools(config, server),
        Target::Remote { url, headers } => mcp_client::probe_remote_tools(url, headers),
    }
}

fn cmd_pin(args: &[String]) -> i32 {
    let target = match parse_target(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("pin {e}");
            return 2;
        }
    };
    let server = match &target {
        Target::Stdio { server, .. } => server.clone(),
        Target::Remote { url, .. } => url.clone(),
    };
    let chain_path = chain_path(args);
    match probe_target(&target) {
        Ok(tools) => {
            let canonical = serde_json::to_string(&tools).unwrap_or_default();
            let mut h = sha2::Sha256::new();
            h.update(canonical.as_bytes());
            let hash = format!("{:x}", h.finalize());

            let mut chain = match store::load(&chain_path) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("chain load failed: {e}");
                    return 2;
                }
            };
            let previous = chain
                .entries
                .last()
                .map(|e| e.hash.clone())
                .unwrap_or_else(|| "0".repeat(64));
            let entry = tamper_audit::AuditEntry::new(
                "mcp-sentinel",
                "pin-tools",
                &server,
                json!({
                    "tools_hash": hash,
                    "tools_count": tools.get("tools").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(0),
                    "target": server,
                }),
                &previous,
            );
            println!(
                "{}",
                json!({"ok": true, "server": server, "tools_hash": hash,
                       "tools_count": tools.get("tools").and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(0),
                       "chain_index": chain.entries.len()})
            );
            chain.entries.push(entry);
            if let Err(e) = store::save(&chain_path, &chain) {
                eprintln!("chain save failed: {e}");
                return 2;
            }
            0
        }
        Err(e) => {
            eprintln!("probe failed: {e}");
            1
        }
    }
}

fn cmd_verify(args: &[String]) -> i32 {
    let target = match parse_target(args) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("verify {e}");
            return 2;
        }
    };
    let server = match &target {
        Target::Stdio { server, .. } => server.clone(),
        Target::Remote { url, .. } => url.clone(),
    };
    let chain_path = chain_path(args);
    let chain = match store::load(&chain_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chain load failed: {e}");
            return 2;
        }
    };
    let pinned = chain
        .entries
        .iter()
        .rev()
        .find(|e| e.action == "pin-tools" && e.resource == server)
        .and_then(|e| e.details.get("tools_hash").and_then(|h| h.as_str()).map(String::from));

    let Some(pinned_hash) = pinned else {
        println!("{}", json!({"ok": false, "error": "no pinned snapshot for this server — run pin first"}));
        return 1;
    };

    match probe_target(&target) {
        Ok(tools) => {
            let canonical = serde_json::to_string(&tools).unwrap_or_default();
            let mut h = sha2::Sha256::new();
            h.update(canonical.as_bytes());
            let hash = format!("{:x}", h.finalize());
            let drift = hash != pinned_hash;
            println!(
                "{}",
                json!({
                    "ok": !drift,
                    "server": server,
                    "pinned_hash": pinned_hash,
                    "current_hash": hash,
                    "drift": drift,
                    "verdict": if drift { "TOOL DEFINITIONS CHANGED since pin — re-approve before trusting this server" } else { "tool definitions match pin" },
                })
            );
            if drift {
                1
            } else {
                0
            }
        }
        Err(e) => {
            eprintln!("probe failed: {e}");
            1
        }
    }
}

fn cmd_verify_chain(args: &[String]) -> i32 {
    let chain_path = chain_path(args);
    let chain = match store::load(&chain_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("chain load failed: {e}");
            return 2;
        }
    };
    let result = tamper_audit::AuditChain::verify(&chain.entries);
    println!(
        "{}",
        json!({
            "ok": result.is_valid(),
            "total_entries": result.total_entries,
            "valid_entries": result.valid_entries,
            "broken_at": result.broken_at,
            "error": result.error,
        })
    );
    if result.is_valid() {
        0
    } else {
        1
    }
}


/// Continuous tools/list monitoring for one stdio server: the Deadbugz
/// mid-session-mutation detector. Each sweep hashes tools/list and compares
/// against the previous sweep; drift is both logged and written into the
/// tamper-evident chain (action "drift-detected"), so the mutation record
/// itself is hash-chained.
///
/// Usage:
///   mcp-sentinel watch --config <file> --server <name> [--interval <secs>] [--chain <file>]
///
/// Exits on Ctrl-C (the chain persists; sweeps resume on next start).
fn cmd_watch(args: &[String]) -> i32 {
    let get = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|p| args.get(p + 1)).cloned()
    };
    let (Some(config), Some(server)) = (get("--config"), get("--server")) else {
        eprintln!("watch requires --config <file> --server <name>");
        return 2;
    };
    let interval: u64 = get("--interval")
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let chain_path = chain_path(args);

    let mut last_hash: Option<String> = None;
    let mut sweep: u64 = 0;
    loop {
        sweep += 1;
        match mcp_client::probe_tools(&config, &server) {
                Ok(tools) => {
                    let canonical = serde_json::to_string(&tools).unwrap_or_default();
                    let mut h = sha2::Sha256::new();
                    h.update(canonical.as_bytes());
                    let hash = format!("{:x}", h.finalize());
                    let drift = last_hash.is_some() && last_hash.as_deref() != Some(hash.as_str());
                    let first = last_hash.is_none();
                    let entry_kind = if drift { "drift-detected" } else { "observe-tools" };
                    println!(
                        "{}",
                        json!({
                            "sweep": sweep, "server": server, "hash": hash, "drift": drift,
                            "first": first, "tools_count": tools.get("tools")
                                .and_then(|t| t.as_array()).map(|a| a.len()).unwrap_or(0),
                        })
                    );
                    if drift {
                        eprintln!(
                            "mcp-sentinel: TOOL DEFINITION DRIFT on `{server}` (sweep {sweep})"
                        );
                    }
                    let mut chain = match store::load(&chain_path) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("chain load failed: {e}");
                            return 2;
                        }
                    };
                    let previous = chain
                        .entries
                        .last()
                        .map(|e| e.hash.clone())
                        .unwrap_or_else(|| "0".repeat(64));
                    chain.entries.push(tamper_audit::AuditEntry::new(
                        "mcp-sentinel-watch",
                        entry_kind,
                        &server,
                        json!({"sweep": sweep, "hash": hash, "drift": drift}),
                        &previous,
                    ));
            if let Err(e) = store::save(&chain_path, &chain) {
                eprintln!("chain save failed: {e}");
            }
            last_hash = Some(hash);
        }
        Err(e) => {
            eprintln!("mcp-sentinel: probe failed (sweep {sweep}): {e}");
        }
    }
        std::thread::sleep(Duration::from_secs(interval));
    }
}
