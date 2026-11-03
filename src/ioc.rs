//! Deadbugz + structural IoC rules for MCP config scanning.
//!
//! Sources: Pillar Security Deadbugz disclosure (2026-08), CSA research note
//! (2026-09), GitHub Advisory GHSA-p6wc-j7x7-ff3v. See
//! docs/mcp-supply-chain-threat-model.md.

use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Finding {
    pub severity: &'static str, // CRITICAL | WARN | INFO
    pub rule: &'static str,
    pub detail: String,
}

/// Known-bad endpoints/paths from published campaigns. Extend as advisories land.
const IOC_HOSTS: &[&str] = &["productivity-suite-mcp.onrender.com"];
const IOC_PATH_PATTERNS: &[&str] = &[".deadbug-mcp.py", ".config/.cache/.sys/"];

/// Servers whose declared purpose is text formatting/summarization but that
/// match an IoC — the Deadbugz bait profile.
const BAIT_SUMMARY_HOSTS: &[&str] = IOC_HOSTS;

pub fn ioc_host_hit(s: &str) -> Option<&'static str> {
    IOC_HOSTS.iter().find(|h| s.contains(*h)).copied()
}

pub fn ioc_path_hit(s: &str) -> Option<&'static str> {
    IOC_PATH_PATTERNS.iter().find(|p| s.contains(*p)).copied()
}

pub fn is_remote(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

pub fn finding(severity: &'static str, rule: &'static str, detail: impl Into<String>) -> Finding {
    Finding { severity, rule, detail: detail.into() }
}

/// Rules applied to a server entry (name + type + url/command/args blob).
pub fn evaluate(name: &str, kind: &str, blob: &str) -> Vec<Finding> {
    let mut out = Vec::new();

    if let Some(host) = ioc_host_hit(blob) {
        out.push(finding(
            "CRITICAL",
            "deadbugz-ioc-endpoint",
            format!("server `{name}` references known campaign endpoint {host}"),
        ));
    }
    if let Some(pat) = ioc_path_hit(blob) {
        out.push(finding(
            "CRITICAL",
            "deadbugz-ioc-hidden-path",
            format!("server `{name}` references known campaign path pattern {pat}"),
        ));
    }
    if kind == "remote" {
        if blob.contains("http://") {
            out.push(finding(
                "WARN",
                "remote-plaintext",
                format!("server `{name}` is a remote MCP over plaintext HTTP"),
            ));
        } else {
            out.push(finding(
                "INFO",
                "remote-server",
                format!("server `{name}` is a remote MCP server — tool definitions are a runtime trust boundary; pin with `mcp-sentinel pin`"),
            ));
        }
    }
    if kind == "local" {
        let lower = blob.to_lowercase();
        for marker in ["curl ", "wget ", "eval", "| sh", "| bash", "base64 -d"] {
            if lower.contains(marker) {
                out.push(finding(
                    "WARN",
                    "command-exec-in-config",
                    format!("server `{name}` command chain contains `{marker}` — review what it executes"),
                ));
            }
        }
        if lower.contains("/tmp/") {
            out.push(finding(
                "WARN",
                "tmp-artifact",
                format!("server `{name}` executes from /tmp — transient artifacts are a staging pattern"),
            ));
        }
    }
    out
}
