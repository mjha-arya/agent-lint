import json
from pathlib import Path

from agent_lint.cli import lint, main, to_sarif
from agent_lint.rules import _pinned_npm, frontmatter

FIX = Path(__file__).parent / "fixtures"


def rules_for(name):
    findings, _ = lint(FIX / name)
    return sorted(f.rule for f in findings)


def test_bad_fixture_hits_every_rule():
    hit = set(rules_for("bad"))
    assert {f"AL{n:03d}" for n in range(1, 12)} <= hit


def test_good_fixture_is_clean():
    assert rules_for("good") == []


def test_exit_codes(capsys):
    assert main([str(FIX / "bad")]) == 1
    assert main([str(FIX / "good")]) == 0
    assert main([str(FIX / "bad"), "--fail-on", "never"]) == 0


def test_secrets_are_redacted(capsys):
    main([str(FIX / "bad"), "--format", "json"])
    out = capsys.readouterr().out
    assert "ghp_aaaaaaaaaaaaaaaa" not in out
    assert "hunter2hunter2" not in out


def test_sarif_is_valid_shape():
    findings, _ = lint(FIX / "bad")
    s = to_sarif(findings)
    assert s["version"] == "2.1.0"
    res = s["runs"][0]["results"]
    assert res and all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in res)
    json.dumps(s)


def test_npm_pinning():
    assert _pinned_npm("@scope/pkg@1.2.3")
    assert _pinned_npm("pkg@0.4.0")
    assert not _pinned_npm("@scope/pkg")
    assert not _pinned_npm("pkg@latest")
    assert not _pinned_npm("pkg@^1.0.0")


def test_frontmatter_multiline():
    fm = frontmatter("---\nname: x\ndescription: >\n  long text\n  here\ntools: Read\n---\nbody")
    assert fm["name"] == "x" and "long text" in fm["description"] and fm["tools"] == "Read"


def test_empty_dir_reports_not_checked(tmp_path, capsys):
    assert main([str(tmp_path)]) == 0
    assert "NOT CHECKED" in capsys.readouterr().out


def test_vscode_and_desktop_configs():
    findings, _ = lint(FIX / "bad")
    files = {(Path(f.file).as_posix(), f.rule) for f in findings}
    assert (".vscode/mcp.json", "AL002") in files
    assert ("claude_desktop_config.json", "AL002") in files


def test_suppression_inline_and_config():
    findings, n = lint(FIX / "suppressed")
    assert n == 2 and findings == []


def test_cli_ignore_flag():
    findings, _ = lint(FIX / "bad", {"AL002", "al006"})
    assert not any(f.rule in {"AL002", "AL006"} for f in findings)


def test_ignore_paths(tmp_path):
    (tmp_path / "vendor").mkdir()
    (tmp_path / "vendor" / ".mcp.json").write_text('{"mcpServers":{"x":{"command":"npx","args":["pkg"]}}}')
    (tmp_path / ".agent-lint.json").write_text('{"ignore_paths": ["vendor/**"]}')
    assert lint(tmp_path) == ([], 0)
