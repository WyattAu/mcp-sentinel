# Agentic skills + MCP supply-chain threat model: what this registry watches

## The pattern (four incidents, one quarter)

| Incident | Vector | Trick |
|---|---|---|
| Deadbugz (2026-08) | GitHub PRs adding MCP config | runtime-gated: benign for 3 tool calls, then tools/list mutates to credential-stealing instructions |
| Mini Shai-Hulud (2026-07) | npm `preinstall` hooks, 631 packages in 22 minutes | GitHub API as exfil channel; CI/CD workflow injection persistence |
| LiteLLM 1.107.0 (2026-10) | PyPI wheel + official container images | payload runs on Python *startup* — no import needed |
| GHAPPIER (2026-09) | npm trusted publishing (valid OIDC provenance!) | provenance attests build origin, not honesty; remote shell deletes itself |

## The controls every advisory recommends (and nobody ships cohesively)

1. **Tool-definition hash pinning** — snapshot `tools/list` responses at
   approval time; alert on ANY subsequent change (Deadbugz mutates exactly
   there, gated on call count)
2. **MCP-server allowlisting** — fail-closed policy on which servers an
   agent may reach (estate: policy-kit)
3. **Config diff scanning** — PR/diff review treats MCP server entries as
   production-credential changes (gitleaks-class tooling, MCP-aware)
4. **Continuous behavioral monitoring** — not install-time static scanning;
   the payload gates on usage, not version or window

## Estate build (mcp-sentinel pitch)

- `mcp-sentinel pin` — snapshot every configured server's tools/list
  into a tamper-evident chain (tamper-audit)
- `mcp-sentinel watch` — daemon: re-probe on `tools/listChanged`,
  alert + block on definition drift (policy-kit enforcement)
- `mcp-sentinel scan` — gitleaks-style PR/diff scanner for MCP config
  entries: known-bad endpoints, hidden local paths (`.deadbug-mcp.py`
  pattern), remote servers added by unfamiliar contributors
- `mcp-sentinel verify` — re-derive the chain, diff live definitions vs
  pinned, emit a signed report

Consumes: tamper-audit, policy-kit, auditlog. Extends: mcp-doctor.
