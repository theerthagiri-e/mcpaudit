"""Correlate per-file signals into repository-level findings."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from . import rules as R
from .scanner import scan_repo


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    evidence: list  # list of "path:line  text"
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _loc(hit) -> str:
    return "%s:%d  %s" % (hit.path, hit.line, hit.text)


def _by_signal(hits) -> dict:
    out = {}
    for h in hits:
        out.setdefault(h.signal, []).append(h)
    return out


def _make(rule_id, hits, severity=None) -> Finding:
    default_sev, title, remediation = R.RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        severity=severity or default_sev,
        title=title,
        evidence=[_loc(h) for h in hits[:8]],
        remediation=remediation,
    )


def analyze(hits) -> list:
    sig = _by_signal(hits)
    findings = []

    has_http = "http_transport" in sig
    bind_all = sig.get("bind_all", [])
    auth_wired = "auth_wired" in sig
    auth_off = sig.get("auth_off", [])
    origin_ok = "origin_check" in sig

    # MCP001 — the money finding: network transport, all-interfaces bind, no auth wired.
    exposed = has_http and bind_all and not auth_wired
    if exposed:
        findings.append(_make("MCP001", bind_all + sig["http_transport"][:2]))

    # MCP006 — exposed AND backed by a cloud/service credential: the high-impact case.
    if exposed and "cred_backed" in sig:
        findings.append(_make("MCP006", sig["cred_backed"]))

    # MCP003 — auth opt-in and off by default.
    if auth_off:
        # High when it combines with an exposed HTTP transport, else medium.
        sev = "high" if (has_http and bind_all) else "medium"
        findings.append(_make("MCP003", auth_off, severity=sev))

    # MCP004 — exposed HTTP transport without origin / DNS-rebinding validation.
    if has_http and bind_all and not origin_ok:
        findings.append(_make("MCP004", bind_all))

    # MCP002 — exec sinks, prioritising those in tool/handler files.
    exec_hits = sig.get("exec_sink", [])
    if exec_hits:
        tool_hits = [h for h in exec_hits if R.TOOL_PATH_HINT.search(h.path)] or exec_hits
        findings.append(_make("MCP002", tool_hits))

    # MCP005 — possible cleartext credential handling.
    if "cleartext_cred" in sig:
        findings.append(_make("MCP005", sig["cleartext_cred"]))

    findings.sort(key=lambda f: -R.SEVERITIES.index(f.severity))
    return findings


def analyze_repo(root: str) -> tuple:
    hits = scan_repo(root)
    return hits, analyze(hits)
