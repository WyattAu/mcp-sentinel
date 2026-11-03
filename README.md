# mcp-sentinel

MCP supply-chain integrity gate. The controls every 2026 incident advisory
recommends — tool-definition hash pinning, config IoC scanning, mid-session
drift detection — in one static Rust binary.

## Why

Four incidents in one quarter: **Deadbugz** (MCP metadata poisoning gated on
call count, delivered via GitHub PRs), **Mini Shai-Hulud** (npm worm, 631
packages), **LiteLLM 1.107.0** (PyPI startup-hook compromise), **GHAPPIER**
(remote shell behind *valid* npm provenance signatures). Tool definitions are
a runtime trust boundary: approving a server once is not approval forever.
Threat model + sources: `docs/mcp-supply-chain-threat-model.md`.

## Commands

```sh
mcp-sentinel scan <path> [--json]
    # discover MCP config files (opencode.json/c, .mcp.json, mcp.json,
    # claude_desktop_config.json, mcp_config.json), extract server entries
    # (V2 mcp.servers / V1 flat mcp / mcpServers), flag Deadbugz IoCs and
    # structural suspicion. Exit 1 on any CRITICAL.

mcp-sentinel pin --config <file> --server <name> [--chain <file>]
    # spawn the stdio server, complete the MCP handshake, hash the
    # tools/list result into a tamper-evident chain (tamper-audit).

mcp-sentinel verify --config <file> --server <name> [--chain <file>]
    # re-probe and compare. Exit 1 on tool-definition drift — the
    # Deadbugz-class mutation detector.

mcp-sentinel verify-chain [--chain <file>]
    # re-derive the hash chain; exit 1 if tampered.
```

CI gate: pin at approval time, `verify` on every run; drift fails the run.

## Threat model

See `docs/mcp-supply-chain-threat-model.md`. The four-incident pattern:
payloads gate on *usage* (call counts, startup hooks), not on version or
install-time content — so install-time static scanning misses them. Runtime
definition pinning does not.

## Roadmap

- Remote-server probing (SSE / streamable HTTP transports)
- `watch` daemon: continuous tools/list monitoring + policy-kit enforcement
- Config diff scanner as a GitHub Action (PR annotation on MCP entries)
- Estate integration: findings exported to the auditlog chain

## License

MIT. See [LICENSE](LICENSE).
