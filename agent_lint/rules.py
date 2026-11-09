"""Rules. Each rule is a function (ctx) -> list[Finding]. Plain code, no model, no network."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

ERROR, WARN, INFO = "error", "warning", "note"


@dataclass
class Finding:
    rule: str
    level: str
    file: str
    line: int
    message: str
    fix: str = ""


@dataclass
class Rule:
    id: str
    name: str
    level: str
    summary: str
    fix: str


RULES: dict[str, Rule] = {r.id: r for r in [
    Rule("AL001", "secret-in-config", ERROR,
         "A credential is stored in plaintext in agent configuration.",
         "Reference an environment variable (\"${VAR}\") instead of the literal value."),
    Rule("AL002", "unpinned-mcp-server", ERROR,
         "An MCP server is launched from a package or image with no pinned version. "
         "An auto-updating dependency inside an agent loop is remote code execution on a delay.",
         "Pin an exact version: `npx -y pkg@1.2.3`, `uvx pkg==1.2.3`, `image@sha256:...`."),
    Rule("AL003", "insecure-mcp-transport", WARN,
         "A remote MCP server is reached over plain http.",
         "Use https for any non-loopback MCP server."),
    Rule("AL004", "unrestricted-shell", ERROR,
         "Permissions allow any shell command without a prompt.",
         "Allow specific commands, e.g. `Bash(npm test:*)`, never `Bash` or `Bash(*)`."),
    Rule("AL005", "permission-prompts-bypassed", ERROR,
         "Permission prompts are disabled for this project.",
         "Remove bypassPermissions; allow-list the specific tools you need instead."),
    Rule("AL006", "subagent-inherits-all-tools", WARN,
         "A subagent has no `tools:` field, so it inherits every tool including shell and write.",
         "Declare the minimum tool list in the frontmatter, e.g. `tools: Read, Grep, Glob`."),
    Rule("AL007", "egress-plus-execution", WARN,
         "One agent can both execute/write and reach the network. That is the shape of a "
         "data-exfiltration path if it ever reads untrusted content.",
         "Split the role: a read-only researcher with web access, a separate builder without it."),
    Rule("AL008", "weak-description", INFO,
         "An agent or skill description is missing or too short to route on reliably.",
         "Say what it does and when to use it, in one or two sentences."),
    Rule("AL009", "pipe-to-shell", ERROR,
         "A hook, skill or agent pipes a downloaded script straight into a shell.",
         "Download, verify a checksum, then run; or install a pinned package."),
    Rule("AL010", "auto-enable-project-mcp", WARN,
         "Every MCP server in the project's .mcp.json is trusted automatically.",
         "Remove enableAllProjectMcpServers and approve servers individually."),
    Rule("AL011", "no-secret-read-deny", INFO,
         "Permissions have no deny rule for reading secret files.",
         "Add `\"deny\": [\"Read(./.env)\", \"Read(./.env.*)\", \"Read(./secrets/**)\"]`."),
]}

SECRET_PATTERNS = [
    ("Anthropic key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9]{32,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
]
SECRETY_KEY = re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|bearer|authorization)")
PLACEHOLDER = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^<.*>$|^(?:x+|\*+|changeme|your[-_].*|placeholder)$", re.I)
PIPE_TO_SHELL = re.compile(r"(curl|wget|iwr|Invoke-WebRequest)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\|\s*iex\b", re.I)
SHELL_TOOLS = {"bash", "powershell"}
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit"}
NET_TOOLS = {"webfetch", "websearch"}


def _f(rule: str, file: Path, line: int, message: str) -> Finding:
    r = RULES[rule]
    return Finding(rule, r.level, str(file), line, message, r.fix)


def _line_of(text: str, needle: str) -> int:
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def redact(s: str) -> str:
    return s[:4] + "…" + f"({len(s)} chars)" if len(s) > 8 else "…"


# ---------- secrets / pipe-to-shell: any scanned file ----------

def scan_text(path: Path, text: str) -> list[Finding]:
    out = []
    for label, pat in SECRET_PATTERNS:
        for m in pat.finditer(text):
            out.append(_f("AL001", path, text.count("\n", 0, m.start()) + 1,
                          f"{label} in plaintext ({redact(m.group(0))})"))
    for m in PIPE_TO_SHELL.finditer(text):
        out.append(_f("AL009", path, text.count("\n", 0, m.start()) + 1,
                      f"pipe-to-shell: `{m.group(0)[:60]}`"))
    return out


# ---------- .mcp.json ----------

def _pinned_npm(spec: str) -> bool:
    name = spec[1:] if spec.startswith("@") else spec
    if "@" not in name:
        return False
    ver = name.rsplit("@", 1)[1]
    return bool(ver) and ver not in {"latest", "next", "*"} and not ver.startswith("^") and not ver.startswith("~")


def check_mcp_server(path: Path, text: str, name: str, cfg: dict) -> list[Finding]:
    out = []
    line = _line_of(text, f'"{name}"')
    cmd = str(cfg.get("command", "")).lower()
    args = [str(a) for a in cfg.get("args", [])]
    base = Path(cmd).name.replace(".cmd", "").replace(".exe", "")
    if base in {"npx", "bunx", "pnpx"} or (base in {"pnpm", "yarn"} and args[:1] == ["dlx"]):
        pkgs = [a for a in args if not a.startswith("-") and a != "dlx"]
        if pkgs and not _pinned_npm(pkgs[0]):
            out.append(_f("AL002", path, line, f"server '{name}' runs `{base} {pkgs[0]}` with no pinned version"))
    elif base in {"uvx", "pipx"}:
        pkgs = [a for a in args if not a.startswith("-") and a != "run"]
        if pkgs and "==" not in pkgs[0] and "@" not in pkgs[0]:
            out.append(_f("AL002", path, line, f"server '{name}' runs `{base} {pkgs[0]}` with no pinned version"))
    elif base in {"docker", "podman"} and "run" in args:
        imgs = [a for a in args[args.index("run") + 1:] if not a.startswith("-") and "=" not in a]
        img = next((a for a in imgs if "/" in a or ":" in a or "@" in a), imgs[-1] if imgs else "")
        if img and "@sha256:" not in img and (":" not in img.split("/")[-1] or img.endswith(":latest")):
            out.append(_f("AL002", path, line, f"server '{name}' runs image `{img}` without a tag or digest"))
    url = str(cfg.get("url", ""))
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])(:|/|$)", url):
        out.append(_f("AL003", path, line, f"server '{name}' uses {url}"))
    for section in ("env", "headers"):
        for k, v in (cfg.get(section) or {}).items():
            if SECRETY_KEY.search(k) and isinstance(v, str) and v and not PLACEHOLDER.match(v.replace("Bearer ", "")):
                if not any(p.search(v) for _, p in SECRET_PATTERNS):  # avoid double-report
                    out.append(_f("AL001", path, _line_of(text, f'"{k}"'),
                                  f"server '{name}' {section}.{k} holds a literal value ({redact(v)})"))
    return out


def check_mcp_json(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    servers = data.get("mcpServers", {}) if isinstance(data, dict) else {}
    out = []
    for name, cfg in servers.items():
        if isinstance(cfg, dict):
            out += check_mcp_server(path, text, name, cfg)
    return out


# ---------- settings.json ----------

def check_settings(path: Path, text: str) -> list[Finding]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    out = []
    perms = data.get("permissions", {}) or {}
    for rule in perms.get("allow", []) or []:
        r = str(rule).replace(" ", "")
        if r in {"Bash", "Bash(*)", "Bash(:*)", "Bash(**)", "PowerShell", "PowerShell(*)"}:
            out.append(_f("AL004", path, _line_of(text, f'"{rule}"'), f"allow rule `{rule}` permits any command"))
    mode = perms.get("defaultMode") or data.get("defaultMode")
    if mode == "bypassPermissions":
        out.append(_f("AL005", path, _line_of(text, "bypassPermissions"), "defaultMode is bypassPermissions"))
    if data.get("skipDangerousModePermissionPrompt"):
        out.append(_f("AL005", path, _line_of(text, "skipDangerousModePermissionPrompt"),
                      "skipDangerousModePermissionPrompt is enabled"))
    if data.get("enableAllProjectMcpServers"):
        out.append(_f("AL010", path, _line_of(text, "enableAllProjectMcpServers"), "enableAllProjectMcpServers is true"))
    deny = " ".join(str(d) for d in perms.get("deny", []) or [])
    if perms and ".env" not in deny and "secret" not in deny.lower():
        out.append(_f("AL011", path, _line_of(text, '"permissions"'), "no deny rule covers .env or secrets files"))
    for name, cfg in (data.get("mcpServers") or {}).items():
        if isinstance(cfg, dict):
            out += check_mcp_server(path, text, name, cfg)
    return out


# ---------- agents and skills (markdown + frontmatter) ----------

def frontmatter(text: str) -> dict[str, str] | None:
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm: dict[str, str] = {}
    key = None
    for raw in text[3:end].splitlines():
        if not raw.strip():
            continue
        m = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", raw)
        if m:
            key = m.group(1).lower()
            fm[key] = m.group(2).strip().strip('"\'')
        elif key:  # continuation / list item
            fm[key] = (fm[key] + " " + raw.strip().lstrip("- ")).strip()
    return fm


def _tools(value: str) -> set[str]:
    value = value.strip("[]")
    return {re.split(r"[(\s]", t.strip().strip('"\''))[0].lower() for t in value.split(",") if t.strip()}


def check_agent_md(path: Path, text: str, kind: str) -> list[Finding]:
    fm = frontmatter(text)
    if fm is None:
        return [_f("AL008", path, 1, f"{kind} has no frontmatter")]
    out = []
    desc = fm.get("description", "")
    if len(desc) < 20:
        out.append(_f("AL008", path, _line_of(text, "description") if desc else 1,
                      f"{kind} '{fm.get('name', path.stem)}' description is {len(desc)} chars"))
    field_name = "tools" if kind == "subagent" else "allowed-tools"
    if kind == "subagent" and "tools" not in fm:
        out.append(_f("AL006", path, 1, f"subagent '{fm.get('name', path.stem)}' declares no tools"))
    tools = _tools(fm.get(field_name, "")) if field_name in fm else set()
    if kind == "subagent" and "tools" not in fm:
        tools = SHELL_TOOLS | WRITE_TOOLS | NET_TOOLS  # inherits everything
    if tools & (SHELL_TOOLS | WRITE_TOOLS) and tools & NET_TOOLS and field_name in fm:
        out.append(_f("AL007", path, _line_of(text, field_name + ":"),
                      f"{kind} '{fm.get('name', path.stem)}' has {sorted(tools & (SHELL_TOOLS | WRITE_TOOLS))} "
                      f"and {sorted(tools & NET_TOOLS)}"))
    return out
