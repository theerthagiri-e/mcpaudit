# Changelog

## 0.2.0

- Add `--skill` mode: static triage for agent SKILL.md packages before install.
  Flags exfiltration/conceal/override prose (SKILL101–103), declared-vs-actual
  permission gaps (SKILL104), env-read-plus-network shape (SKILL105), and
  dangerous shell constructs in bundled scripts (SKILL106). Reads files only.
- Text and JSON reporters for skill mode; `--fail-on` works as a CI gate.
- Tests + evil/clean skill fixtures.

## 0.1.3

- Static MCP server triage (MCP001–006). Initial public release.
