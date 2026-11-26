"""Walk a repository and extract signals from source lines. No code is executed."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import rules as R

_LINE_COMMENT = {
    "py": re.compile(r"(^|\s)#.*$"),
    "js": re.compile(r"//.*$"),
    "go": re.compile(r"//.*$"),
}
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


@dataclass
class Hit:
    signal: str
    path: str
    line: int
    text: str


def _lang(path: str):
    return R.LANG_BY_EXT.get(os.path.splitext(path)[1].lower())


def _strip_comments(source: str, lang: str) -> list:
    """Return a list of (line_number, code_without_comments).

    Comments are blanked, not removed, so line numbers stay accurate. This stops
    defensive annotations (which often mention "0.0.0.0", "injection", etc.) from
    being scored as signals.
    """
    source = _BLOCK_COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)
    out = []
    pattern = _LINE_COMMENT.get(lang)
    for i, line in enumerate(source.splitlines(), 1):
        code = pattern.sub(lambda m: m.group(1) if m.lastindex else "", line) if pattern else line
        out.append((i, code))
    return out


def scan_file(path: str, rel: str) -> list:
    if R.VENDOR_PATH.search(rel.replace("\\", "/")):
        return []  # vendored third-party code, not the project's own
    lang = _lang(path)
    try:
        if os.path.getsize(path) > R.MAX_FILE_BYTES:
            return []
        with open(path, encoding="utf-8", errors="replace") as fh:
            source = fh.read()
    except OSError:
        return []

    hits = []
    for line_no, code in _strip_comments(source, lang or ""):
        if not code.strip():
            continue
        for signal, patterns in R.SIGNALS.items():
            for regex, langs in patterns:
                if langs is not None and lang != langs:
                    continue
                if regex.search(code):
                    hits.append(Hit(signal, rel, line_no, code.strip()[:200]))
                    break  # one hit per signal per line is enough
    return hits


def scan_repo(root: str) -> list:
    """Return all signal hits under root, skipping vendored and build directories."""
    hits = []
    root = os.path.abspath(root)
    if os.path.isfile(root):
        return scan_file(root, os.path.basename(root))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in R.SKIP_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() not in R.LANG_BY_EXT:
                continue
            if R.SKIP_FILE.search(name):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            hits.extend(scan_file(full, rel))
    return hits
