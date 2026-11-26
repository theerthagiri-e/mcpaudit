# Finding exposed MCP servers — the hunt workflow

The bug class: an MCP server runs an HTTP/SSE transport, binds all interfaces,
and wires no authentication. `mcpaudit` confirms and ranks; **GitHub code search
finds the candidates.** Run discovery on your own machine where `gh` is
authenticated.

> Reality check before you spend hours: this class is being mass-filed by
> scanner shops (PT Security, Knostic and others). A generic exposed server is a
> dup race you will often lose. Your edge is a **cloud/infra** server where you
> can write the account-level impact a generic scanner can't. Filter for those.

## Step 1 — Discover candidates (your machine, authed `gh`)

Each query prints `owner/repo` matches. Code search is noisy; it's a net, not a
verdict.

```bash
# Python FastMCP servers binding all interfaces
gh search code 'FastMCP "0.0.0.0"' --language Python --limit 50 --json repository \
  | jq -r '.[].repository.nameWithOwner' | sort -u

# Python SSE/Starlette MCP transports on all interfaces
gh search code 'SseServerTransport "0.0.0.0"' --language Python --limit 50 --json repository \
  | jq -r '.[].repository.nameWithOwner' | sort -u

# TypeScript streamable/SSE transports on all interfaces
gh search code 'StreamableHTTPServerTransport "0.0.0.0"' --limit 50 --json repository \
  | jq -r '.[].repository.nameWithOwner' | sort -u
gh search code 'SSEServerTransport "0.0.0.0"' --limit 50 --json repository \
  | jq -r '.[].repository.nameWithOwner' | sort -u

# Auth defaulting off
gh search code '"oauth_enabled" "false"' --language Python --limit 50 --json repository \
  | jq -r '.[].repository.nameWithOwner' | sort -u
```

Collect the output into `repos.txt` (one `owner/repo` per line). Prefer cloud /
infra / IaC / DB servers, recently pushed, low stars. Drop anything from a vendor
with a real security team unless you already see the hole.

### Bias discovery toward credential-backed servers (your edge)

These find servers that both expose a transport and hold a cloud/data credential
— the MCP006 case, where the impact is account/database access you can write:

```bash
gh search code 'SseServerTransport AWS_ACCESS_KEY_ID' --language Python --limit 50 \
  --json repository | jq -r '.[].repository.nameWithOwner' | sort -u
gh search code 'FastMCP DATABASE_URL "0.0.0.0"' --language Python --limit 50 \
  --json repository | jq -r '.[].repository.nameWithOwner' | sort -u
gh search code 'StreamableHTTPServerTransport PERSONAL_ACCESS_TOKEN' --limit 50 \
  --json repository | jq -r '.[].repository.nameWithOwner' | sort -u
```

After `scan_batch.sh`, **open the MCP006 hits first** — exposed *and*
credential-backed. That is the finding a generic scanner can't impact-rate and
the one hardest to dup.

## Step 2 — Confirm and rank (the scanner)

```bash
./scripts/scan_batch.sh repos.txt
```

Open every repo that scores `critical=1` (MCP001). Read the transport file:
does an auth check gate the `/mcp` (or `/sse`, `/messages`) routes, or not?

## Step 3 — Live-confirm (cheap, yours to run)

Clone the one candidate, start it on localhost per its README, and:

```bash
curl -s -X POST http://127.0.0.1:<port>/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

If it returns the tool list with no credential, the exposure is real. Do **not**
test any server you don't own over the network — stand up your own instance.

## Step 4 — Dup-check BEFORE writing anything (this is the step that bit us)

```bash
# existing advisories / CVEs for the repo
gh search issues --repo <owner/repo> 'security OR CVE OR SSRF OR auth' --limit 20
```
Also check: the repo's GitHub Security Advisories tab, osv.dev, and a web search
for "<repo> CVE". If it's already reported, move to the next candidate.

## Step 5 — Report

- Repo has a `SECURITY.md` → follow it (usually a private GitHub Security
  Advisory, which mints a CVE with your name).
- No policy → open a private advisory via the repo's Security tab, or email the
  maintainer. Never a public issue for an unpatched auth bypass.
- Lead with the **cloud impact**: what the exposed tools do to the AWS/k8s/DB
  account. That's the part that makes it yours and hard to dismiss.
