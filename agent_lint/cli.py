"""agent-lint: least-privilege and supply-chain linter for Claude Code agent setups."""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .rules import (ERROR, INFO, RULES, WARN, Finding, check_agent_md, check_mcp_json,
                    check_settings, scan_text)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
ORDER = {ERROR: 0, WARN: 1, INFO: 2}


def discover(root: Path) -> list[tuple[Path, str]]:
    """Return (path, kind) for every agent-config file under root."""
    found = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        d = Path(dirpath)
        parts = d.parts
        for f in files:
            p = d / f
            if f == ".mcp.json" or (f.endswith(".json") and f.startswith("mcp") and ".cursor" in parts):
                found.append((p, "mcp"))
            elif f in {"settings.json", "settings.local.json"} and parts and parts[-1] == ".claude":
                found.append((p, "settings"))
            elif f.endswith(".md") and "agents" in parts and ".claude" in parts:
                found.append((p, "subagent"))
            elif f == "SKILL.md":
                found.append((p, "skill"))
            elif f in {"CLAUDE.md", "AGENTS.md"} or (f.endswith((".sh", ".ps1", ".py")) and "hooks" in parts):
                found.append((p, "text"))
    return found


def lint(root: Path) -> tuple[list[Finding], int]:
    files = discover(root)
    findings: list[Finding] = []
    for path, kind in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = path.relative_to(root) if path.is_relative_to(root) else path
        batch = scan_text(rel, text)
        if kind == "mcp":
            batch += check_mcp_json(rel, text)
        elif kind == "settings":
            batch += check_settings(rel, text)
        elif kind in {"subagent", "skill"}:
            batch += check_agent_md(rel, text, kind)
        findings += batch
    findings.sort(key=lambda f: (ORDER[f.level], f.file, f.line))
    return findings, len(files)


def to_sarif(findings: list[Finding]) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "agent-lint", "version": __version__,
                "informationUri": "https://github.com/mjha-arya/agent-lint",
                "rules": [{"id": r.id, "name": r.name,
                           "shortDescription": {"text": r.summary},
                           "help": {"text": r.fix},
                           "defaultConfiguration": {"level": r.level}} for r in RULES.values()],
            }},
            "results": [{
                "ruleId": f.rule, "level": f.level,
                "message": {"text": f"{f.message}. Fix: {f.fix}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": Path(f.file).as_posix()},
                    "region": {"startLine": f.line}}}],
            } for f in findings],
        }],
    }


ICON = {ERROR: "✖", WARN: "▲", INFO: "•"}


def to_text(findings: list[Finding], nfiles: int) -> str:
    lines = []
    for f in findings:
        lines.append(f"{ICON[f.level]} {f.rule} {RULES[f.rule].name}  {Path(f.file).as_posix()}:{f.line}")
        lines.append(f"    {f.message}")
        lines.append(f"    fix: {f.fix}")
    c = {lvl: sum(f.level == lvl for f in findings) for lvl in ORDER}
    lines.append(f"\n{nfiles} config file(s) scanned · {c[ERROR]} error · {c[WARN]} warning · {c[INFO]} note")
    if nfiles == 0:
        lines.append("NOT CHECKED: no .claude/, .mcp.json, SKILL.md or hook files found under this path.")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent-lint", description=__doc__)
    ap.add_argument("path", nargs="?", default=".", help="project root (default: .)")
    ap.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    ap.add_argument("--output", "-o", help="write the report to a file")
    ap.add_argument("--fail-on", choices=["error", "warning", "note", "never"], default="error",
                    help="exit 1 when a finding at this level or worse exists (default: error)")
    ap.add_argument("--list-rules", action="store_true")
    ap.add_argument("--version", action="version", version=f"agent-lint {__version__}")
    a = ap.parse_args(argv)
    if a.list_rules:
        for r in RULES.values():
            print(f"{r.id}  {r.level:<7}  {r.name:<30} {r.summary}")
        return 0
    root = Path(a.path).resolve()
    findings, nfiles = lint(root)
    if a.format == "sarif":
        out = json.dumps(to_sarif(findings), indent=2)
    elif a.format == "json":
        out = json.dumps({"files_scanned": nfiles, "findings": [asdict(f) for f in findings]}, indent=2)
    else:
        out = to_text(findings, nfiles)
    if a.output:
        Path(a.output).write_text(out, encoding="utf-8")
    else:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        print(out)
    if a.fail_on == "never":
        return 0
    worst = min((ORDER[f.level] for f in findings), default=99)
    return 1 if worst <= ORDER[a.fail_on] else 0


if __name__ == "__main__":
    sys.exit(main())
