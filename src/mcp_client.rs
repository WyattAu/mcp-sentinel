//! Minimal MCP stdio client: spawn a local server, complete the handshake,
//! return the tools/list result. Newline-delimited JSON-RPC (MCP stdio).

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Stdio};
use std::time::Duration;

pub struct McpConnection {
    child: Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl McpConnection {
    pub fn spawn(command: &str, args: &[String]) -> Result<Self, String> {
        let mut child = std::process::Command::new(command)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn {command}: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let reader = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        let mut conn = McpConnection { child, stdin, reader, next_id: 1 };
        conn.handshake()?;
        Ok(conn)
    }

    fn handshake(&mut self) -> Result<(), String> {
        let init = json!({
            "jsonrpc": "2.0", "id": self.next_id, "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-sentinel", "version": "0.1.0"},
            }
        });
        let resp = self.request(init)?;
        if resp.get("result").is_none() {
            return Err("initialize returned no result".into());
        }
        self.next_id += 1;
        let notified = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        self.notify(notified)
    }

    fn notify(&mut self, payload: Value) -> Result<(), String> {
        let line = format!("{payload}\n");
        self.stdin.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())
    }

    fn request(&mut self, mut payload: Value) -> Result<Value, String> {
        let id = self.next_id;
        payload["id"] = json!(id);
        let line = format!("{payload}\n");
        self.stdin.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        self.wait_response(id, &Duration::from_secs(15))
    }

    fn wait_response(&mut self, id: u64, _timeout: &Duration) -> Result<Value, String> {
        // Read lines until the response with the matching id arrives.
        // Notifications (no id) are skipped.
        loop {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("server closed stdout".into());
            }
            let Ok(v) = serde_json::from_str::<Value>(line.trim()) else { continue };
            if v.get("id").and_then(|x| x.as_u64()) == Some(id) {
                if let Some(err) = v.get("error") {
                    return Err(format!("rpc error: {err}"));
                }
                return Ok(v);
            }
        }
    }

    pub fn tools_list(&mut self) -> Result<Value, String> {
        let req = json!({"jsonrpc": "2.0", "id": self.next_id, "method": "tools/list", "params": {}});
        self.next_id += 1;
        let resp = self.request(req)?;
        let result = resp
            .get("result")
            .cloned()
            .ok_or_else(|| "tools/list returned no result".to_string())?;
        // Canonicalize: BTreeMap-backed Value sorts keys deterministically, so
        // serde_json::to_string of the re-parsed value is a stable hash input.
        let canon: Value = serde_json::from_str(&serde_json::to_string(&result).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(canon)
    }
}

impl Drop for McpConnection {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

pub fn probe_tools(config_path: &str, server: &str) -> Result<Value, String> {
    let (command, args) = crate::scan::load_server_config(config_path, server)?;
    let mut conn = McpConnection::spawn(&command, &args)?;
    conn.tools_list()
}

// ─── remote (streamable HTTP) probing ───

/// Probe a remote MCP server over streamable HTTP: initialize -> (session) ->
/// tools/list. Returns the tools/list result Value for hashing.
pub fn probe_remote_tools(
    url: &str,
    extra_headers: &[(String, String)],
) -> Result<Value, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .into();

    // 1. initialize
    let init_body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-sentinel", "version": "0.2.0"},
        }
    })
    .to_string();
    let mut req = agent.post(url);
    req = req.header("Content-Type", "application/json");
    req = req.header("Accept", "application/json, text/event-stream");
    req = req.header("mcp-protocol-version", "2025-06-18");
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let mut resp = req
        .send(init_body.as_bytes())
        .map_err(|e| format!("initialize POST failed: {e}"))?;
    let session_id = resp
        .headers()
        .get("mcp-session-id")
        .map(|v| String::from_utf8_lossy(v.as_bytes()).to_string());
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    if status >= 400 {
        return Err(format!("initialize HTTP {status}: {}", text.chars().take(200).collect::<String>()));
    }
    let init_result = parse_body(&text)?;

    // 2. notifications/initialized (no body expected; 202 tolerated)
    let note = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
    let mut note_req = agent.post(url);
    note_req = note_req.header("Content-Type", "application/json");
    note_req = note_req.header("Accept", "application/json, text/event-stream");
    for (k, v) in extra_headers {
        note_req = note_req.header(k.as_str(), v.as_str());
    }
    let _ = note_req
        .send(note)
        .map_err(|e| format!("initialized notification failed: {e}"));

    // 3. tools/list
    let list_body = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        .to_string();
    let mut req = agent.post(url);
    req = req.header("Content-Type", "application/json");
    req = req.header("Accept", "application/json, text/event-stream");
    req = req.header("mcp-protocol-version", "2025-06-18");
    for (k, v) in extra_headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if let Some(sid) = &session_id {
        req = req.header("mcp-session-id", sid);
    }
    let mut resp = req
        .send(list_body.as_bytes())
        .map_err(|e| format!("tools/list POST failed: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
    if status >= 400 {
        return Err(format!("tools/list HTTP {status}: {}", text.chars().take(200).collect::<String>()));
    }
    let resp_val = parse_body(&text)?;
    resp_val
        .get("result")
        .cloned()
        .ok_or_else(|| "tools/list returned no result".to_string())
}

fn parse_body(text: &str) -> Result<Value, String> {
    let trimmed = text.trim();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return serde_json::from_str(trimmed).map_err(|e| format!("JSON parse: {e}"));
    }
    // SSE: concatenate all data: lines (one event per JSON-RPC response)
    let mut data = String::new();
    for line in trimmed.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            data.push_str(rest.trim_start());
        }
    }
    if data.is_empty() {
        return Err("empty SSE body".into());
    }
    serde_json::from_str(&data).map_err(|e| format!("SSE data parse: {e}"))
}
