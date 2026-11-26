import json
import os

from mcpaudit.analyzer import analyze, analyze_repo, Finding
from mcpaudit.scanner import scan_file, _strip_comments, Hit
from mcpaudit.cli import main

HERE = os.path.dirname(__file__)
VULN = os.path.join(HERE, "fixtures", "vuln_server")
SAFE = os.path.join(HERE, "fixtures", "safe_server")


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def test_vendored_dependency_paths_are_skipped():
    from mcpaudit.rules import VENDOR_PATH
    for p in ("python-sdk/examples/servers/simple-auth/server.py",
              "time/uvicorn/server.py", "time/pydantic_settings/sources.py",
              "src/examples/demo.py", "vendor/starlette/applications.py"):
        assert VENDOR_PATH.search(p), p
    for p in ("app/main.py", "src/myserver/transport.py", "server.py"):
        assert not VENDOR_PATH.search(p), p


def test_multi_segment_test_filenames_are_skipped():
    from mcpaudit.rules import SKIP_FILE
    for name in ("http-security.spec.unit.ts", "server.test.integration.ts",
                 "foo_test.go", "conftest.py"):
        assert SKIP_FILE.search(name), name
    for name in ("server.ts", "manifest.py", "testament.py"):
        assert not SKIP_FILE.search(name), name


def test_comments_are_stripped_so_annotations_dont_score():
    # A defensive comment mentioning the bad bind must not produce a bind_all hit.
    src = 'x = 1  # beware host="0.0.0.0" here\nactual = 2\n'
    out = _strip_comments(src, "py")
    assert '0.0.0.0' not in out[0][1]
    assert out[0][0] == 1 and out[1][0] == 2  # line numbers preserved


def test_bind_all_needs_a_bind_context_not_a_bare_literal():
    hits = scan_file.__wrapped__ if hasattr(scan_file, "__wrapped__") else scan_file
    # a literal inside an allow-list set, with no bind keyword, is not flagged
    from mcpaudit.rules import SIGNALS
    bind_patterns = SIGNALS["bind_all"]
    detection_set_line = 'ALL_INTERFACES = new Set(["0.0.0.0", "::"])'
    assert not any(rx.search(detection_set_line) for rx, _ in bind_patterns)
    bind_line = 'app.listen(3000, "0.0.0.0")'
    assert any(rx.search(bind_line) for rx, _ in bind_patterns)


def test_vulnerable_fixture_triggers_core_findings():
    hits, findings = analyze_repo(VULN)
    ids = _ids(findings)
    assert "MCP001" in ids  # exposed + unauthenticated
    assert "MCP002" in ids  # exec sink
    assert "MCP003" in ids  # auth opt-in off
    assert "MCP004" in ids  # no origin check
    assert "MCP006" in ids  # exposed AND cloud-credential-backed
    # MCP001 is critical and sorted first
    assert findings[0].rule_id == "MCP001" and findings[0].severity == "critical"


def test_safe_fixture_is_clean_of_the_exposure_finding():
    hits, findings = analyze_repo(SAFE)
    ids = _ids(findings)
    # auth is wired and host defaults to localhost -> no MCP001/MCP004
    assert "MCP001" not in ids
    assert "MCP004" not in ids
    assert "MCP002" not in ids


def test_auth_off_alone_is_medium_not_high():
    hits = [Hit("auth_off", "config.py", 10, "oauth_enabled: bool = False")]
    findings = analyze(hits)
    assert _ids(findings) == ["MCP003"]
    assert findings[0].severity == "medium"  # no exposed transport alongside it


def test_cli_exit_codes_and_json(capsys, tmp_path):
    assert main([VULN]) == 1
    out = capsys.readouterr().out
    assert "MCP001" in out

    assert main([VULN, "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["critical"] >= 1

    assert main([SAFE, "--fail-on", "high"]) == 0

    missing = tmp_path / "nope"
    # a missing path scans as empty, not an error
    assert main([str(missing)]) == 0
