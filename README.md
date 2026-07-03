# mcp-glpi-secure

MCP server for GLPI with **zero third-party runtime dependencies** — the MCP
protocol (JSON-RPC 2.0 over stdio) is implemented directly, so there is no
dependency tree to carry CVEs. `npm audit` reports **0 vulnerabilities**.

Built as a security gateway, not a raw API proxy:

- **Least privilege.** Boots in one mode (`read-only` default). Tools whose
  capability isn't granted are never registered — the model can't see them.
- **No delete power at all.** There is no delete/purge tool and the client
  cannot issue HTTP DELETE to GLPI. Removal is a human operation done in GLPI.
- **Input validation.** Every tool argument is checked against a strict schema
  (`additionalProperties: false` — blocks mass-assignment) before any call.
- **Egress hardening.** Single fixed origin (host allowlist), TLS required,
  request timeout, no redirect following (anti-SSRF), sanitized errors.
- **Secret hygiene.** Tokens loaded from env or `*_FILE` mounts; redacted in
  all logs. Logs go to stderr; stdout is the JSON-RPC stream only.

## Configuration (environment)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `GLPI_URL` | yes | — | e.g. `https://glpi.internal/glpi`. Must be https. |
| `GLPI_MCP_MODE` | no | `read-only` | `read-only` \| `read-write` \| `admin` |
| `GLPI_APP_TOKEN` | recommended | — | GLPI API App-Token. `_FILE` variant supported. |
| `GLPI_USER_TOKEN` | recommended | — | Preferred auth. `_FILE` variant supported. |
| `GLPI_USERNAME` / `GLPI_PASSWORD` | fallback | — | Basic auth if no user token. |
| `GLPI_TIMEOUT_MS` | no | `15000` | Per-request timeout. |
| `GLPI_ALLOW_INSECURE` | no | — | `1` to permit http:// (lab only). |

Prefer `GLPI_USER_TOKEN` bound to a **restricted GLPI profile** — least
privilege starts in GLPI itself.

## Install (for agents)

**One-time setup** — build once and put the `mcp-glpi-secure` command on PATH.
`npm install` auto-builds via the `prepare` script:

```bash
npm install      # installs devDeps + builds dist/ (prepare)
npm link         # exposes the `mcp-glpi-secure` command globally
```

Then register it in your agent. Pick one:

**A. Claude Code — one command:**

```bash
claude mcp add glpi \
  --env GLPI_URL=https://glpi.internal/glpi \
  --env GLPI_USER_TOKEN=xxxxxxxx \
  --env GLPI_MCP_MODE=read-only \
  -- mcp-glpi-secure
```

**B. Project config file** — create `.mcp.json` at your project root (Claude
Code auto-discovers it). Using `${VAR}` keeps secrets out of the file — they
come from the environment:

```json
{
  "mcpServers": {
    "glpi": {
      "command": "mcp-glpi-secure",
      "env": {
        "GLPI_URL": "${GLPI_URL}",
        "GLPI_USER_TOKEN": "${GLPI_USER_TOKEN}",
        "GLPI_MCP_MODE": "${GLPI_MCP_MODE:-read-only}"
      }
    }
  }
}
```

**C. Claude Desktop** — add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "glpi": {
      "command": "mcp-glpi-secure",
      "env": {
        "GLPI_URL": "https://glpi.internal/glpi",
        "GLPI_USER_TOKEN": "xxxxxxxx",
        "GLPI_MCP_MODE": "read-only"
      }
    }
  }
}
```

**Without `npm link`** (no global command): use
`"command": "node", "args": ["/abs/path/mcp-glpi-secure/dist/index.js"]`.

In production, run behind an egress allowlist that permits only the GLPI host.

## Verify

```bash
npm run build && npm test    # schema / policy / redaction self-checks
npm audit                    # -> found 0 vulnerabilities
```
