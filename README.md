# mcpaudit

Static triage for MCP (Model Context Protocol) servers. Finds the security
posture problems that are producing CVEs across the MCP ecosystem: HTTP/SSE
transports exposed on all interfaces with no authentication, auth that defaults
off, missing Origin / DNS-rebinding validation, shell-exec sinks in tool
handlers, and cleartext credential handling.

It reads source only. It never executes the target. Point it at a repo before
you install the server, or across many repos to find the ones worth a manual look.

## Why

When an agent connects to an MCP server it trusts it completely — no sandbox, no
per-tool permission prompt. A server that binds `0.0.0.0` with auth off is an
unauthenticated remote tool-execution endpoint. Researchers have found thousands
exposed on the public internet. `mcpaudit` ranks which servers have that shape.

## Install

```
pip install .
```

## Use

```
mcpaudit path/to/mcp-server
mcpaudit path/to/mcp-server --format json --output report.json
mcpaudit path/to/mcp-server --fail-on critical   # CI gate: exit 1 on criticals
```

Scan many at once:

```
./scripts/scan_batch.sh repos.txt    # one owner/repo per line
```

## Checks

| Rule | Severity | What it flags |
| --- | --- | --- |
| MCP001 | critical | HTTP/SSE transport binds all interfaces with no auth wired |
| MCP002 | high | Shell-exec sink (`exec`/`execSync`/`shell:true`/`os.system`/`shell=True`/`eval`) in a handler |
| MCP003 | high/medium | Authentication opt-in and defaulting off |
| MCP004 | medium | HTTP transport with no Origin / DNS-rebinding validation |
| MCP005 | low | Possible cleartext credential handling |

MCP001 is the combination that matters: a network transport **and** an
all-interfaces bind **and** no authentication wired into the routes. A single
all-interfaces string inside an allow-list, or a safe `spawn(cmd, args)` with no
shell, is deliberately not flagged.

## Honest limits

- This is **triage, not proof**. Every finding needs manual confirmation. Absence
  of findings is not a clean bill of health.
- It is pattern-based, not a full parser. It can miss auth that is wired in a way
  it doesn't recognise, and it can flag auth-off defaults that a deployment
  overrides. Read the evidence lines.
- Test code is skipped by default.
- Languages: Python, TypeScript/JavaScript, Go.

## Skill package triage (`--skill`)

MCP servers are one agent supply chain. Installable **skills** — a `SKILL.md`
plus optional scripts that run inside your coding agent with its file, shell and
network access — are another, and a code scanner misses the part that matters:
the dangerous surface is *instructions in natural language*, and the agent, not
a script, carries them out.

Run it on a skill package before you install one:

```
mcpaudit path/to/skill --skill
mcpaudit path/to/skill --skill --format json --fail-on critical
```

### Checks

| Rule | Severity | What it flags |
| --- | --- | --- |
| SKILL101 | critical | Prose that tells the agent to read secrets/credentials/env and send them off-box |
| SKILL102 | high | Prose that tells the agent to hide actions or output from the user |
| SKILL103 | high | Prose that tells the agent to ignore/override prior or system instructions or safety |
| SKILL104 | high | Bundled scripts do more than the package's declared permissions admit |
| SKILL105 | medium | A script reads environment variables **and** makes network calls (exfil shape) |
| SKILL106 | high | A dangerous shell construct ships in a script (`curl \| sh`, `chmod 777`, `rm -rf /`, base64-decoded exec) |

### Honest limits (read these)

- **SKILL104 needs a self-declared permission to compare against.** It fires only
  when the frontmatter declares something like `network: false` and a script then
  uses the network. Most skills declare nothing, so 104 stays silent there — you
  lean on 101/102/105/106. This is deliberate: the tool does not invent a
  permission baseline the package never stated.
- Prose detection is pattern-based. Paraphrase can evade it; a clean result is
  not a safety certificate. It is triage to decide what deserves a careful read.
- It does not execute the skill, does not vet skill *quality*, and says nothing
  about the behaviour of any marketplace-hosted tools the skill calls.
- A skill runs its instructions in **your** agent's session. Read every finding in
  the file before you install.

## Roadmap

- Call-graph check for "auth defined but never wired" (the most common real bug)
- Taint from tool-input schema to exec sink
- Dependency-manifest checks (known-vulnerable MCP SDK versions)

## Develop

```
pip install -e ".[dev]"
pytest
```

## License

MIT
