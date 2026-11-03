//! Persistence for the tamper-evident chain (JSON array of AuditEntry).
//! Same shape as dissect-evidence's store; genesis previous_hash is the
//! 64-zero hash per tamper-audit convention.

use serde::{Deserialize, Serialize};
use std::path::Path;
use tamper_audit::AuditEntry;

#[derive(Serialize, Deserialize)]
pub struct ChainFile {
    pub schema: u32,
    pub entries: Vec<AuditEntry>,
}

pub fn load(path: &Path) -> Result<ChainFile, String> {
    if !path.exists() {
        return Ok(ChainFile { schema: 1, entries: Vec::new() });
    }
    let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| format!("chain file corrupt: {e}"))
}

pub fn save(path: &Path, chain: &ChainFile) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    std::fs::write(
        path,
        serde_json::to_string_pretty(chain).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}
