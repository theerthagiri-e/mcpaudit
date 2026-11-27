from mcpaudit.skillscan import scan_skill


def _ids(findings):
    return {f.rule_id for f in findings}


def test_malicious_skill_flags_exfil_conceal_override():
    findings, meta = scan_skill("tests/fixtures/evil_skill")
    ids = _ids(findings)
    assert "SKILL101" in ids          # read creds + send off-box
    assert "SKILL102" in ids          # conceal from user
    assert "SKILL103" in ids          # override prior instructions
    assert "SKILL104" in ids          # declared network:false but script uses network
    sev = {f.rule_id: f.severity for f in findings}
    assert sev["SKILL101"] == "critical"
    assert meta["observed"]["network"] is True


def test_clean_skill_has_no_findings():
    findings, meta = scan_skill("tests/fixtures/clean_skill")
    assert findings == []
    assert meta["saw_skill_md"] is True


def test_non_skill_dir_warns_no_skill_md(tmp_path):
    (tmp_path / "notes.txt").write_text("just some text")
    findings, meta = scan_skill(str(tmp_path))
    assert meta["saw_skill_md"] is False


def test_scanning_scoped_to_skill_md_dirs_not_whole_repo():
    # Scanning the repo root must not prose-scan README.md or script-scan
    # src/mcpaudit/skillscan.py (its regex literals would trip script rules).
    findings, meta = scan_skill(".")
    files = {ev.split(":")[0] for f in findings for ev in f.evidence}
    assert not any("README" in p for p in files)
    assert not any("skillscan.py" in p for p in files)
    # It still reaches the evil fixture package.
    assert any("evil_skill" in p for p in files)


def test_pointing_at_single_skill_md_file():
    findings, meta = scan_skill("tests/fixtures/evil_skill/SKILL.md")
    assert meta["saw_skill_md"] is True
    assert "SKILL101" in {f.rule_id for f in findings}
