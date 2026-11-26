"""Signal patterns and finding metadata for the MCP server audit.

The scanner extracts low-level *signals* from source lines; the analyzer
correlates them per repository into *findings*. Keeping the two separate is
what lets a single defensive string (e.g. an all-interfaces address inside an
allow-list) avoid being mistaken for a vulnerable bind.
"""

from __future__ import annotations

import re

SEVERITIES = ["low", "medium", "high", "critical"]

# --- language detection ---
LANG_BY_EXT = {
    ".py": "py",
    ".ts": "js", ".tsx": "js", ".mts": "js", ".cts": "js",
    ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js",
    ".go": "go",
}
SKIP_DIRS = {".git", "node_modules", "dist", "build", "vendor", ".venv",
             "venv", "__pycache__", ".mypy_cache", "coverage", ".next",
             "test", "tests", "__tests__", "testdata", "e2e", "spec"}
SKIP_FILE = re.compile(r"\.(?:test|spec)\.|[._]test\.|^conftest\.py$", re.IGNORECASE)

# Third-party code copied straight into the repo tree (not under node_modules/.venv).
# Hits inside these are the dependency's own code, not the project's, so they're
# skipped — otherwise every repo that vendors the MCP SDK, uvicorn or pydantic
# would be flagged for the library's example/transport code.
VENDOR_PATH = re.compile(
    r"(?:^|/)(?:"
    r"uvicorn|pydantic|pydantic_core|pydantic_settings|starlette|anyio|httpx|httpcore|"
    r"sniffio|certifi|h11|h2|idna|click|fastapi|boto3|botocore|openai|anthropic|"
    r"site-packages|dist-packages|python-sdk"
    r")/|(?:^|/)examples?/",
    re.IGNORECASE,
)
MAX_FILE_BYTES = 1_000_000

# --- signals ---
# Each signal: name -> list of (compiled regex, langs or None for any).
_ALL_IFACE = r"""["'](?:0\.0\.0\.0|::0?|0)["']"""
_BIND_KW = r"\b(?:host|listen|bind|serve|uvicorn|run|sse|http)\b"


def _rx(pattern, flags=re.IGNORECASE):
    return re.compile(pattern, flags)


SIGNALS = {
    # Binding to all interfaces, in a context that looks like an actual bind
    # (an all-interfaces literal AND a binding keyword on the same line).
    "bind_all": [
        (re.compile(_ALL_IFACE + r".*" + _BIND_KW, re.IGNORECASE), None),
        (re.compile(_BIND_KW + r".*" + _ALL_IFACE, re.IGNORECASE), None),
    ],
    # The server speaks an HTTP/SSE transport (vs stdio-only, which isn't network-exposed).
    "http_transport": [
        (_rx(r"SSEServerTransport|StreamableHTTPServerTransport|streamableHttp"), None),
        (_rx(r"express\(\)|app\.listen\(|createServer\("), "js"),
        (_rx(r"uvicorn\.run\(|FastAPI\(|Starlette\(|starlette|aiohttp|Flask\(|HTTPServer\("), "py"),
        (_rx(r"http\.ListenAndServe\(|gin\.|mux\.|chi\."), "go"),
    ],
    # Auth is opt-in and defaults off.
    "auth_off": [
        (_rx(r"oauth[_ ]?enabled\s*[:=]\s*False"), "py"),
        (_rx(r"require[_ ]?auth\w*\s*[:=]\s*False"), None),
        (_rx(r"auth[_ ]?enabled\s*[:=]\s*(?:False|false)\b"), None),
        (_rx(r"""AUTH[_ ]?ENABLED["']?\s*,\s*["']false"""), None),
        (_rx(r"""(?:oauth|auth)[_ ]?enabled.*os\.getenv\([^)]*["']false"""), "py"),
        (_rx(r"enable[_ ]?auth\s*[:=]\s*false"), "js"),
    ],
    # Auth actually wired into request handling (mitigating).
    "auth_wired": [
        (_rx(r"authMiddleware|requireAuth\b|verifyToken\(|checkAuth\("), "js"),
        (_rx(r"validate_auth_header\s*\(|verify_token\s*\(|check_auth\s*\(|Depends\(\s*\w*auth"), "py"),
        (_rx(r"app\.use\(\s*\w*[Aa]uth"), "js"),
        (_rx(r"@require_auth|require_auth\s*=\s*True|require_auth\s*:\s*True"), None),
    ],
    # Origin validation / DNS-rebinding protection (mitigating).
    "origin_check": [
        (_rx(r"is_valid_origin|validate_origin|check_origin|is_potential_dns_rebinding"), None),
        (_rx(r"allowed[_ ]?hosts|allowedHosts|buildDefaultAllowedHosts"), None),
        (_rx(r"DNSRebindingProtection|enableDnsRebindingProtection"), None),
    ],
    # Command/code execution sinks.
    "exec_sink": [
        # Shell-invoking sinks only. A bare spawn()/execFile() with an argument
        # array and no shell is the safe pattern and is deliberately not flagged.
        (_rx(r"execSync\(|child_process\.\w*exec|\bcp\.exec\(|\beval\(|shell\s*:\s*true"), "js"),
        (_rx(r"os\.system\(|subprocess\.\w+\([^)]*shell\s*=\s*True|os\.popen\(|\beval\(|\bexec\("), "py"),
        (_rx(r"exec\.Command\([^)]*(?:sh|bash|-c)"), "go"),
    ],
    # The server is backed by a cloud / service / data credential. When this
    # combines with an exposed, unauthenticated transport, the impact is access
    # to whatever that credential can reach — the differentiated finding.
    "cred_backed": [
        (_rx(r"AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|aws_access_key_id"), None),
        (_rx(r"GITLAB[_A-Z]*TOKEN|PERSONAL_ACCESS_TOKEN|GITHUB_TOKEN|\bGH_TOKEN\b"), None),
        (_rx(r"DATABASE_URL|POSTGRES|MYSQL|MONGODB?_URI|connection[_ ]?string|\bDSN\b"), None),
        (_rx(r"K8S_TOKEN|KUBECONFIG|kube_?config|service[_-]?account[_-]?token"), None),
        (_rx(r"AZURE_[A-Z_]*(?:KEY|SECRET|TOKEN)|GOOGLE_APPLICATION_CREDENTIALS|GCP_[A-Z_]*KEY"), None),
    ],
    # Possible cleartext credential storage/logging.
    "cleartext_cred": [
        (_rx(r"(?:token|secret|password|api[_-]?key)\b.{0,30}"
             r"(?:open\(|writeFile|fs\.write|\.write\(|logger\.|console\.log|\bprint\()"), None),
    ],
}

# Signals that indicate a network transport handler file (for scoping exec sinks).
TOOL_PATH_HINT = re.compile(r"(?:^|/)(?:tools?|handlers?|server|mcp)(?:/|\.|_)", re.IGNORECASE)

# rule_id -> (default severity, title, remediation)
RULES = {
    "MCP001": (
        "critical",
        "HTTP/SSE transport binds all interfaces with no authentication wired",
        "Bind to localhost by default, and require authentication on every MCP route "
        "before any non-loopback bind is allowed. An exposed, unauthenticated MCP server "
        "is a remote tool-execution endpoint for anyone who can reach the port.",
    ),
    "MCP002": (
        "high",
        "Command/code execution sink in a tool handler",
        "Never build a shell command from tool input. Use argument arrays without a shell, "
        "validate against an allow-list, and drop eval/exec on model-supplied data.",
    ),
    "MCP003": (
        "high",
        "Authentication is opt-in and defaults off",
        "Default authentication on. Require it whenever the transport is not loopback-only.",
    ),
    "MCP004": (
        "medium",
        "HTTP transport with no Origin / DNS-rebinding validation",
        "Validate the Origin header and the Host against an allow-list so a browser-based "
        "DNS-rebinding attack cannot reach a local server.",
    ),
    "MCP005": (
        "low",
        "Possible cleartext credential handling",
        "Do not write tokens, keys or passwords to disk or logs in cleartext.",
    ),
    "MCP006": (
        "critical",
        "Exposed unauthenticated transport is backed by a cloud/service credential",
        "This is the high-impact case: an unauthenticated caller reaches tools that act "
        "with the server's cloud/data credential, so the exposure is access to whatever "
        "that credential can reach (the account, the database, the repo). Fix the auth "
        "exposure first; scope the credential to least privilege second.",
    ),
}
