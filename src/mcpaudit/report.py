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


# --- skill-package reporting ---------------------------------------------------

_SK_ORDER = ("critical", "high", "medium", "low", "info")


def _sk_summary(findings):
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in _SK_ORDER}


def skill_to_json(target, findings, meta) -> str:
    return json.dumps({
        "mode": "skill",
        "target": target,
        "saw_skill_md": meta.get("saw_skill_md", False),
        "declared_permissions": meta.get("declared", {}),
        "observed_in_scripts": meta.get("observed", {}),
        "summary": _sk_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }, indent=2)


def skill_to_text(target, findings, meta) -> str:
    lines = ["mcpaudit skill report", "target: %s" % target]
    if not meta.get("saw_skill_md"):
        lines.append("warning: no SKILL.md found — is this a skill package?")
    counts = _sk_summary(findings)
    lines.append("findings: " + "  ".join("%s=%d" % (s, counts[s]) for s in _SK_ORDER))
    decl, obs = meta.get("declared", {}), meta.get("observed", {})
    if decl or any(obs.values()):
        lines.append("declared: %s" % (decl or "(none)"))
        lines.append("observed in scripts: %s" % {k: v for k, v in obs.items() if v})
    lines.append("")
    if not findings:
        lines.append("No findings. Prose and scripts look clean to static triage.")
        lines.append("This does not vet skill QUALITY or the behaviour of any Agensi tools it calls.")
        return "\n".join(lines) + "\n"
    for f in sorted(findings, key=lambda x: _SK_ORDER.index(x.severity)):
        lines.append("[%s] %s  %s" % (f.severity.upper(), f.rule_id, f.title))
        for ev in f.evidence:
            lines.append("    %s" % ev)
        lines.append("    fix: %s" % f.remediation)
        lines.append("")
    lines.append("A skill runs its instructions in YOUR agent's session. Confirm each finding "
                 "in the file before you install.")
    return "\n".join(lines) + "\n"
