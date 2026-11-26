"""Text and JSON output."""

from __future__ import annotations

import json
from collections import Counter

from . import rules as R


def _summary(findings):
    counts = Counter(f.severity for f in findings)
    return {s: counts.get(s, 0) for s in reversed(R.SEVERITIES)}


def to_json(target, hits, findings) -> str:
    return json.dumps({
        "target": target,
        "files_with_signals": len({h.path for h in hits}),
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def to_text(target, hits, findings) -> str:
    lines = ["mcpaudit report", "target: %s" % target]
    counts = _summary(findings)
    lines.append("findings: " + "  ".join("%s=%d" % (s, counts[s]) for s in counts))
    lines.append("")
    if not findings:
        lines.append("No findings. (Triage tool — absence of findings is not a clean bill of health.)")
        return "\n".join(lines) + "\n"
    for f in findings:
        lines.append("[%s] %s  %s" % (f.severity.upper(), f.rule_id, f.title))
        for ev in f.evidence:
            lines.append("    %s" % ev)
        lines.append("    fix: %s" % f.remediation)
        lines.append("")
    lines.append("Every finding needs manual confirmation; this is static triage, not proof.")
    return "\n".join(lines) + "\n"
