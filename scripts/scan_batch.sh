#!/usr/bin/env bash
# Clone (shallow) and scan a list of MCP server repos, ranked by severity.
# Usage: ./scripts/scan_batch.sh repos.txt   (one "owner/repo" per line)
# Reads source only; never runs the cloned code.
set -u
list="${1:?usage: scan_batch.sh <repos.txt>}"
here="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  dir="$work/$(echo "$repo" | tr '/' '_')"
  if git clone -q --depth 1 "https://github.com/$repo.git" "$dir" 2>/dev/null; then
    line="$(PYTHONPATH="$here/src" python3 -m mcpaudit.cli "$dir" 2>/dev/null | grep '^findings:')"
    printf '%-45s %s\n' "$repo" "$line"
  else
    printf '%-45s clone failed\n' "$repo"
  fi
done < "$list"
