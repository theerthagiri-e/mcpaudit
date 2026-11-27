"""Static triage of agent SKILL.md packages before you install one.

Defensive counterpart to the MCP-server scanner: a skill package is a bundle of
natural-language instructions plus optional scripts that run inside your coding
agent with its file, shell and network access. This module reads a skill package
and flags the two things a code-pattern gate misses:

  1. Prose that steers the agent to exfiltrate, hide actions, or override its
     own instructions. No code required — the agent is the execution engine.
  2. A gap between the permissions the package declares and what its scripts
     actually do.

Reads files only. Runs nothing. Scope is one skill package (a SKILL.md and its
sibling scripts/references), not a marketplace and not a live service.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")

# --- prose intent patterns (matched against SKILL.md body, case-insensitive) ---
# Each entry: (rule_id, default_severity, title, [compiled patterns], remediation)

_P = lambda s: re.compile(s, re.IGNORECASE)

_SECRET = r"(?:\.env\b|env(?:ironment)? var|secrets?|credentials?|tokens?|api[_ -]?keys?|passwords?|\.aws|\.ssh|id_rsa|keychain)"
_SEND = r"(?:send|posts?|upload|exfiltrat|curl|fetch|webhook|https?://|transmit|to an? (?:server|url|endpoint|webhook))"
EXFIL = [
    _P(r"\b(?:read|cat|print|collect|gather|load|grab|dump)\b.{0,60}" + _SECRET),
    _P(_SECRET + r".{0,80}\b" + _SEND),
    _P(r"\bbase64\b.{0,40}\b(?:send|posts?|upload|curl|fetch|http)"),
]

CONCEAL = [
    _P(r"\b(do not|don'?t|never)\b.{0,30}\b(tell|inform|mention|show|notify|alert)\b.{0,20}\b(the )?user\b"),
    _P(r"\b(silently|quietly|without (telling|informing|notifying|the user knowing)|behind the scenes|in the background)\b.{0,40}\b(run|send|read|collect|execute|delete|modify)\b"),
    _P(r"\bhide\b.{0,30}\b(this|the|output|command|step)\b.{0,20}\b(from|user)\b"),
    _P(r"\b(keep|make).{0,20}\bsecret\b"),
]

OVERRIDE = [
    _P(r"\bignore\b.{0,30}\b(previous|prior|earlier|above|system)\b.{0,20}\binstructions?\b"),
    _P(r"\b(disregard|override|bypass|turn off|disable)\b.{0,30}\b(safety|guardrail|policy|rule|restriction|instruction)s?\b"),
    _P(r"\byou are now\b.{0,40}\b(unrestricted|jailbroken|developer mode|no (longer )?bound)\b"),
    _P(r"\bregardless of\b.{0,20}\b(policy|safety|what you (were|are) told)\b"),
]

PROSE_RULES = [
    ("SKILL101", "critical", "Instruction to read credentials/secrets and send them off-box", EXFIL,
     "A skill must never tell the agent to read .env, cloud/SSH credentials, tokens or keys and transmit "
     "them. This is credential exfiltration driven through the agent's own tools, invisible to a code scan. "
     "Do not install. If this is your own skill, remove it."),
    ("SKILL102", "high", "Instruction to hide actions or output from the user", CONCEAL,
     "A skill must not tell the agent to act silently or conceal steps from the user. Concealment is the "
     "defining move of a malicious skill; there is no legitimate reason for it."),
    ("SKILL103", "high", "Instruction to ignore or override prior/system instructions or safety", OVERRIDE,
     "A skill is task guidance, not a context reset. Prompt-injection phrasing aimed at the host agent's "
     "instructions or safety has no place in a legitimate skill."),
]

# --- script behaviour patterns (matched against bundled scripts) ---
SCRIPT_NET = _P(r"requests\.(get|post|put)|urllib|httpx|http\.client|socket\.socket|fetch\(|axios|XMLHttpRequest|\bcurl\b|\bwget\b|Invoke-WebRequest|\bnc\b|/dev/tcp/")
SCRIPT_SHELL = _P(r"os\.system|subprocess\.(run|call|Popen)|shell\s*=\s*True|child_process|execSync|spawnSync|\beval\(|\bexec\(")
SCRIPT_FS_WRITE = _P(r"open\([^)]*['\"][wa]|fs\.write|writeFile|shutil\.|os\.remove|os\.unlink|\brm\s+-rf\b")
SCRIPT_ENV = _P(r"os\.environ|process\.env|getenv|\bENV\[|\$\{?[A-Z_]*(TOKEN|SECRET|KEY|PASSWORD|CRED)")
SCRIPT_DANGER = _P(r"curl\b[^|]*\|\s*(ba)?sh|wget\b[^|]*\|\s*(ba)?sh|chmod\s+777|rm\s+-rf\s+/|:\s*\(\)\s*\{\s*:|base64\s+-d")

PROSE_EXT = {".md"}
SCRIPT_EXT = {".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl"}


@dataclass
class SkillFinding:
    rule_id: str
    severity: str
    title: str
    evidence: list = field(default_factory=list)   # ["path:line  text", ...]
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id, "severity": self.severity, "title": self.title,
            "evidence": self.evidence, "remediation": self.remediation,
        }


def _iter_files(root: str):
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "node_modules", "__pycache__", ".venv"}]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def _lines(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read().splitlines()
    except (OSError, UnicodeError):
        return []


def _strip_frontmatter(lines):
    """Return (body_lines_with_original_numbers, frontmatter_text)."""
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                return list(enumerate(lines[i + 1:], start=i + 2)), "\n".join(lines[1:i])
    return list(enumerate(lines, start=1)), ""


def _declared_perms(frontmatter: str) -> dict:
    """Best-effort read of self-declared permissions from frontmatter.

    Agensi's model is a declared-permission card; many skills carry hints like
    `network: false` / `permissions: [shell]`. We read loosely and only use this
    to contrast with observed script behaviour. Absence is 'undeclared', not 'false'.
    """
    fm = frontmatter.lower()
    perms = {}
    for key, pat in (("network", r"network"), ("shell", r"shell|terminal|exec"),
                     ("filesystem", r"file[_ ]?(system|write)|write[_ ]?files?"), ("env", r"env(ironment)?[_ ]?var")):
        m = re.search(pat + r"\s*[:=]\s*(true|false|yes|no|none)", fm)
        if m:
            perms[key] = m.group(1) in ("true", "yes")
    return perms


def _scan_prose(path, numbered):
    out = []
    # Whitespace-collapsed full text so a pattern can match a sentence that the
    # author wrapped across several lines.
    flat = re.sub(r"\s+", " ", " ".join(t for _, t in numbered))
    for rule_id, sev, title, pats, rem in PROSE_RULES:
        ev, seen_lines = [], False
        for ln, t in numbered:
            if any(p.search(t) for p in pats):
                ev.append("%s:%d  %s" % (path, ln, t.strip()[:160]))
                seen_lines = True
        if not seen_lines:
            for p in pats:
                m = p.search(flat)
                if m:
                    ev.append("%s:(wrapped)  ...%s..." % (path, m.group(0)[:140]))
                    break
        if ev:
            out.append(SkillFinding(rule_id, sev, title, ev[:8], rem))
    return out


def _scan_script(path, numbered):
    obs = {"network": False, "shell": False, "filesystem": False, "env": False}
    ev = {"network": [], "shell": [], "filesystem": [], "env": [], "danger": []}
    for ln, t in numbered:
        rec = "%s:%d  %s" % (path, ln, t.strip()[:160])
        if SCRIPT_NET.search(t):
            obs["network"] = True; ev["network"].append(rec)
        if SCRIPT_SHELL.search(t):
            obs["shell"] = True; ev["shell"].append(rec)
        if SCRIPT_FS_WRITE.search(t):
            obs["filesystem"] = True; ev["filesystem"].append(rec)
        if SCRIPT_ENV.search(t):
            obs["env"] = True; ev["env"].append(rec)
        if SCRIPT_DANGER.search(t):
            ev["danger"].append(rec)
    return obs, ev


def _find_skill_roots(root: str):
    """Return the package root dir for every SKILL.md under `root`.

    A skill package is a SKILL.md plus its sibling files (scripts/, references/).
    We anchor on SKILL.md so pointing --skill at an ordinary repo does not prose-
    scan its docs or script-scan its source. If `root` is itself a SKILL.md, its
    directory is the package.
    """
    if os.path.isfile(root):
        return [os.path.dirname(root) or "."] if os.path.basename(root) == "SKILL.md" else []
    roots = []
    for path in _iter_files(root):
        if os.path.basename(path) == "SKILL.md":
            roots.append(os.path.dirname(path) or ".")
    return sorted(set(roots))


def scan_skill(root: str):
    """Scan the skill package(s) under `root`. Returns (list[SkillFinding], meta)."""
    skill_roots = _find_skill_roots(root)
    if not skill_roots:
        return [], {"saw_skill_md": False, "declared": {}, "observed": {},
                    "note": "no SKILL.md found; not a skill package"}

    findings = []
    declared = {}
    observed = {"network": False, "shell": False, "filesystem": False, "env": False}
    danger_ev, env_ev, net_ev = [], [], []

    for pkg in skill_roots:
        for path in _iter_files(pkg):
            # Stay inside this package: a nested SKILL.md starts its own package.
            if os.path.basename(path) == "SKILL.md" and (os.path.dirname(path) or ".") != pkg:
                continue
            ext = os.path.splitext(path)[1].lower()
            base = os.path.basename(path)
            if base == "SKILL.md" or ext in PROSE_EXT:
                raw = _lines(path)
                numbered, fm = _strip_frontmatter(raw)
                if base == "SKILL.md":
                    declared.update(_declared_perms(fm))
                findings.extend(_scan_prose(path, numbered))
            if ext in SCRIPT_EXT:
                raw = _lines(path)
                obs, ev = _scan_script(path, list(enumerate(raw, start=1)))
                for k in observed:
                    observed[k] = observed[k] or obs[k]
                danger_ev += ev["danger"]; env_ev += ev["env"]; net_ev += ev["network"]

    saw_skill_md = True

    # SKILL104 — declared-vs-actual permission mismatch
    for perm, label in (("network", "network access"), ("shell", "shell/exec"),
                        ("filesystem", "file writes"), ("env", "environment-variable reads")):
        if declared.get(perm) is False and observed[perm]:
            findings.append(SkillFinding(
                "SKILL104", "high",
                "Declared permissions understate what the scripts do (%s)" % label,
                (net_ev if perm == "network" else env_ev if perm == "env" else danger_ev)[:4]
                or ["(see scripts; %s observed while declared false)" % label],
                "The package declares %s off but a bundled script uses it. A declared-permission "
                "card the host does not enforce is not a control. Trust the scripts, not the card." % label,
            ))

    # SKILL105 — env read co-located with network in scripts (silent-exfil shape)
    if observed["env"] and observed["network"]:
        findings.append(SkillFinding(
            "SKILL105", "medium",
            "Script reads environment variables and also makes network calls",
            (env_ev[:2] + net_ev[:2]) or [],
            "Reading env vars and sending network traffic in the same package is the exfiltration "
            "shape. Confirm the env values never reach the network. Not conclusive on its own.",
        ))

    # SKILL106 — outright dangerous command in a script
    if danger_ev:
        findings.append(SkillFinding(
            "SKILL106", "high",
            "Dangerous shell construct in a bundled script",
            danger_ev[:8],
            "curl-piped-to-shell, chmod 777, rm -rf /, fork bombs or base64-decoded execution should "
            "never ship in a skill that runs in your session.",
        ))

    meta = {"saw_skill_md": saw_skill_md, "declared": declared, "observed": observed}
    return findings, meta
