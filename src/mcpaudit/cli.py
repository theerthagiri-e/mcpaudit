"""Command line entry point for mcpaudit."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from . import rules as R
from .analyzer import analyze_repo
from .report import to_json, to_text


def build_parser():
    p = argparse.ArgumentParser(
        prog="mcpaudit",
        description="Static triage for MCP servers: exposed/unauthenticated transports, "
                    "exec sinks, weak auth defaults. Reads source only; runs nothing.",
    )
    p.add_argument("--version", action="version", version="mcpaudit " + __version__)
    p.add_argument("path", help="path to an MCP server repo or source file")
    p.add_argument("--skill", action="store_true",
                   help="scan an agent SKILL.md package (prose intent + declared-vs-actual "
                        "permissions) instead of an MCP server")
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--fail-on", choices=R.SEVERITIES, default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    p.add_argument("--output", help="write the report to this file instead of stdout")
    return p


def _run_skill(args) -> int:
    from .skillscan import scan_skill, SEVERITIES as SK_SEV
    from .report import skill_to_json, skill_to_text
    try:
        findings, meta = scan_skill(args.path)
    except Exception as exc:  # noqa: BLE001
        print("mcpaudit: error: %s" % exc, file=sys.stderr)
        return 2
    report = (skill_to_json(args.path, findings, meta) if args.format == "json"
              else skill_to_text(args.path, findings, meta))
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")
    # --fail-on reuses the shared severity order; skill severities extend it.
    order = SK_SEV
    try:
        threshold = order.index(args.fail_on)
    except ValueError:
        threshold = order.index("high")
    return 1 if any(order.index(f.severity) >= threshold for f in findings) else 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.skill:
        return _run_skill(args)
    try:
        hits, findings = analyze_repo(args.path)
    except Exception as exc:  # noqa: BLE001
        print("mcpaudit: error: %s" % exc, file=sys.stderr)
        return 2

    report = to_json(args.path, hits, findings) if args.format == "json" else to_text(args.path, hits, findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    else:
        sys.stdout.write(report if report.endswith("\n") else report + "\n")

    threshold = R.SEVERITIES.index(args.fail_on)
    return 1 if any(R.SEVERITIES.index(f.severity) >= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
