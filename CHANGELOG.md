# Changelog

## 0.2.0 — 2026-11-09
- **New config sources:** VS Code `.vscode/mcp.json` (`servers` block), Claude Desktop `claude_desktop_config.json`, and `~/.claude.json` per-project MCP servers.
- **Suppressions:** inline `<!-- agent-lint: ignore ALxxx -->`, a project `.agent-lint.json` (`ignore`, `ignore_paths`), and a `--ignore` CLI flag.
- Fix: no crash when stdout has no `reconfigure` (piped or embedded use).
- Only `mcp.json` directly inside `.cursor/` or `.vscode/` is treated as MCP config.
- The repo now lints itself in CI through its own Action.

## 0.1.0 — 2026-11-09
- First release: 11 rules (AL001–AL011), text/JSON/SARIF output, composite GitHub Action.
