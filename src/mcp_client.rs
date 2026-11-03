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
