# mcp-watchdog

[![CI](https://github.com/bountyyfi/mcp-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/bountyyfi/mcp-watchdog/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/mcp-watchdog)](https://pypi.org/project/mcp-watchdog/)
[![Downloads](https://img.shields.io/pypi/dm/mcp-watchdog)](https://pypi.org/project/mcp-watchdog/)
[![GitHub stars](https://img.shields.io/github/stars/bountyyfi/mcp-watchdog)](https://github.com/bountyyfi/mcp-watchdog/stargazers)
[![Python](https://img.shields.io/pypi/pyversions/mcp-watchdog)](https://pypi.org/project/mcp-watchdog/)
[![License](https://img.shields.io/pypi/l/mcp-watchdog)](https://github.com/bountyyfi/mcp-watchdog/blob/main/LICENSE)

<!-- mcp-name: io.github.bountyyfi/mcp-watchdog -->

MCP security proxy that sits between AI coding assistants and MCP servers, detecting and blocking all known MCP attack classes. Works with any MCP server (tools, resources, prompts) on macOS, Linux, and Windows.

Catches **Rug Pulls**, **Tool Poisoning**, **Tool Shadowing**, **Name Squatting**, **Parameter Injection**, **SSRF**, **Command Injection**, **SQL Injection**, **Reverse Shell**, **Supply Chain Impersonation**, **Token Leakage**, **OAuth Confused Deputy**, **Session Smuggling**, **Context Leakage**, **Email Header Injection**, **False-Error Escalation**, **Preference Manipulation**, **ANSI Escape Injection**, **MCP Parasite**, **Thanatos** (all 4 layers), **SANDWORM_MODE**-style prompt injection, **Resource Content Injection**, **Prompt Template Injection**, **Sampling Hijack**, and **Elicitation Credential Harvesting** — before any of it reaches your AI assistant.

## Why this exists

MCP (Model Context Protocol) servers have full access to your AI assistant's context. A malicious or compromised server can:

- **Inject hidden instructions** into tool descriptions (`<IMPORTANT>` blocks telling the AI to exfiltrate credentials)
- **Silently redefine tools** after initial approval (Rug Pull attacks)
- **Shadow trusted tools** by injecting cross-server override instructions in tool descriptions (100% ASR on Claude Desktop)
- **Squat tool names** by registering duplicate tool names from different servers
- **Steal system prompts and conversation history** via parameter injection (HiddenLayer attack)
- **Access cloud metadata** via SSRF through URI parameters (MCP fURI, 36.7% of servers vulnerable)
- **Execute arbitrary commands** via shell metacharacters in tool arguments
- **Inject SQL** via tool arguments to SQLite/database MCP servers (Trend Micro disclosure)
- **Spawn reverse shells** to C2 servers (JFrog found 3 PyPI + npm packages with identical reverse shell payloads)
- **Impersonate legitimate packages** via typosquatting (fake Postmark MCP server - 1,643 downloads)
- **Leak API keys and tokens** (GitHub PATs, AWS keys, Slack tokens, JWTs) in responses
- **Hijack OAuth flows** via malformed authorization endpoints (CVE-2025-6514, 437K+ dev environments)
- **Inject messages into sessions** via agent session smuggling (A2A attacks)
- **Silently BCC emails** to attacker addresses via email header injection (postmark-mcp incident)
- **Trigger privilege escalation** via fake error messages designed to manipulate AI into granting elevated access
- **Manipulate tool selection** via persuasive language in descriptions biasing which tools the AI chooses
- **Hide instructions** via ANSI escape sequences and bidirectional text overrides invisible in terminal UIs
- **Profile your behavior** by collecting commit timestamps, deploy windows, and activity patterns
- **Encode payloads steganographically** inside normal-looking JSON responses
- **Propagate across servers** - output from Server A influences calls to Server B
- **Persist across sessions** by writing state to project files outside declared scope
- **Escape filesystem sandboxes** via symlink attacks bypassing path restrictions
- **Exfiltrate data via URL params** - sensitive tokens embedded in `https://evil.com/steal?data=SECRET`
- **Poison schema fields** - injection in parameter defaults, enums, and nested schema values (CyberArk FSP)
- **Flood approval requests** to cause consent fatigue, then slip in destructive actions
- **Replay OAuth tokens** across servers via audience mismatch (RFC 8707 violation)
- **Inject fake notifications** (`tools/list_changed`) to trigger tool re-fetching for rug pulls
- **Poison resource content** — `resources/read` responses can contain prompt injection payloads targeting the AI model
- **Inject via prompt templates** — `prompts/get` returned messages are a direct LLM injection vector
- **Hijack sampling requests** — malicious servers use `sampling/createMessage` to control LLM behavior with injected system prompts
- **Harvest credentials via elicitation** — `elicitation/create` (MCP 2025-11-25) lets servers phish users for passwords, API keys, and tokens
- **Flood resource update notifications** — rapid `notifications/resources/updated` events trigger re-reads of now-poisoned resources

mcp-watchdog intercepts all JSON-RPC traffic and applies multi-layer detection before any data reaches your AI model.

## What it catches

| Attack Class | Detection Layer | Rule | Severity |
|---|---|---|---|
| SANDWORM_MODE `<IMPORTANT>` injection | SMAC-L3 | SMAC-5 | Critical |
| HTML comment injection | SMAC-L3 | SMAC-1 | High |
| Zero-width unicode steganography | SMAC-L3 | SMAC-1 | High |
| ANSI escape sequence injection | SMAC-L3 | SMAC-1 | High |
| Bidirectional text overrides (LRE/RLO/LRI) | SMAC-L3 | SMAC-1 | High |
| Markdown reference link exfiltration | SMAC-L3 | SMAC-2 | High |
| Credential-seeking patterns | SMAC-L3 | SMAC-5 | Critical |
| Token/secret leakage (GitHub, AWS, Slack, JWT, OpenAI, Stripe, Discord, npm, PyPI, Supabase, Sendgrid, Twilio, Vault, Datadog, GCP, Azure, PEM keys) | SMAC-L3 | SMAC-6 | Critical |
| Homoglyph `<IMPORTANT>` injection (Greek Ι, Cyrillic А) | SMAC-L3 | SMAC-5 | Critical |
| HTML-encoded `&lt;IMPORTANT&gt;` injection | SMAC-L3 | SMAC-5 | Critical |
| Role injection markers (`[SYSTEM]:`, `[ADMIN]:`, `[ASSISTANT]:`) | SMAC-L3 | SMAC-5 | Critical |
| URL-encoded zero-width characters (`%E2%80%8B`) | SMAC-L3 | SMAC-1 | High |
| Double-encoded HTML entities (`&amp;#x200b;`) | SMAC-L3 | SMAC-1 | High |
| Double-encoded path traversal (`..%252f`) | Input Sanitizer | CMD-INJECT | High |
| Split-line tag evasion (`<IMPOR\nTANT>`) | SMAC-L3 | SMAC-5 | Critical |
| Space-split token evasion (`sk_ live_`) | SMAC-L3 | SMAC-6 | Critical |
| Unlabeled secret key detection (`secret_key:`, `private_key:`) | SMAC-L3 | SMAC-6 | Critical |
| Token exfiltration via URL params (Stripe, npm, PyPI, Sendgrid, Vault, Datadog, Discord, Azure keys) | URL Filter | EXFIL | Critical |
| Rug Pull (silent tool redefinition) | Tool Registry | RUG-PULL | Critical |
| Sneaky tool addition (new tools after initial registration) | Tool Registry | RUG-PULL | High |
| Tool removal after establishing trust | Tool Registry | RUG-PULL | High |
| Tool Shadowing (cross-server desc pollution) | Tool Shadow | SHADOW | Critical |
| Tool Name Squatting (duplicate names across servers) | Tool Shadow | SHADOW | Critical |
| Preference Manipulation (biasing tool selection) | Tool Shadow | SHADOW | High |
| Cross-server tool reference in descriptions | Tool Shadow | SHADOW | High |
| Parameter injection (`system_prompt`, `conversation_history`) | Param Scanner | PARAM-INJECT | Critical |
| Suspicious parameter patterns | Param Scanner | PARAM-INJECT | High |
| Full Schema Poisoning (defaults, enums, nested fields) | Param Scanner | PARAM-INJECT | Critical |
| SSRF to cloud metadata (AWS/GCP/Azure IMDS) | URL Filter | SSRF | Critical |
| SSRF to localhost / internal networks | URL Filter | SSRF | High |
| Data exfiltration via URL parameters (Slack CVE-2025-34072) | URL Filter | EXFIL | Critical |
| Base64-encoded token exfiltration in URL params | URL Filter | EXFIL | Critical |
| Shell metacharacter injection | Input Sanitizer | CMD-INJECT | Critical |
| Command injection patterns | Input Sanitizer | CMD-INJECT | Critical |
| Path traversal attacks | Input Sanitizer | CMD-INJECT | High |
| SQL injection (UNION SELECT, DROP TABLE, etc.) | Input Sanitizer | SQL-INJECT | Critical |
| Reverse shell patterns (bash /dev/tcp, nc -e, mkfifo) | Input Sanitizer | REVERSE-SHELL | Critical |
| Email header injection (BCC exfiltration) | Tool Shadow | EMAIL-INJECT | Critical |
| Email comma injection (multiple recipients in to/cc fields) | Tool Shadow | EMAIL-INJECT | Critical |
| False-error escalation (fake errors triggering privilege escalation) | Tool Shadow | ESCALATION | High |
| Supply chain typosquatting | Registry Checker | SUPPLY-CHAIN | Critical |
| Known malicious server patterns | Registry Checker | SUPPLY-CHAIN | Critical |
| OAuth authorization endpoint injection (CVE-2025-6514) | OAuth Guard | OAUTH | Critical |
| Excessive OAuth scope requests | OAuth Guard | OAUTH | High |
| Suspicious OAuth redirect URIs | OAuth Guard | OAUTH | Critical |
| OAuth javascript:/data:/vbscript: redirect URIs | OAuth Guard | OAUTH | Critical |
| OAuth open redirect via query parameters | OAuth Guard | OAUTH | Critical |
| Token audience mismatch / replay (RFC 8707) | OAuth Guard | TOKEN-REPLAY | Critical |
| MCP sampling exploitation (message + system prompt injection) | Proxy | SAMPLING | High |
| Elicitation credential harvesting (password, token, api_key fields) | Proxy | ELICITATION | Critical |
| Elicitation message injection | Proxy | ELICITATION | Critical |
| Resource content injection (`resources/read` responses) | Proxy | CMD-INJECT | Critical |
| Resource description poisoning (`resources/list` responses) | Proxy | SMAC-5 | Critical |
| Resource template description poisoning | Proxy | SMAC-5 | Critical |
| Prompt message injection (`prompts/get` responses) | Proxy | SMAC-5 | Critical |
| Prompt description poisoning (`prompts/list` responses) | Proxy | SMAC-5 | Critical |
| Prompt argument schema injection | Proxy | SMAC-5 | Critical |
| Session smuggling (orphaned/injected responses) | Flow Tracker | SESSION | Critical |
| Cross-server data propagation (JWTs, UUIDs, API keys) | Flow Tracker | CROSS-SERVER | High |
| Context leakage between servers | Proxy | CONTEXT-LEAK | High |
| Consent fatigue / approval flooding | Rate Limiter | RATE-LIMIT | High |
| Burst flooding (rapid-fire tool calls) | Rate Limiter | RATE-LIMIT | Critical |
| Notification event injection (tools/list_changed, resources/updated) | Rate Limiter | NOTIF-INJECT | Critical |
| Windows command injection (cmd.exe, powershell -enc) | Input Sanitizer | CMD-INJECT | Critical |
| Behavioral fingerprinting | Behavioral Monitor | DRIFT | High |
| Scope creep (credential field access) | Behavioral Monitor | DRIFT | Critical |
| Credential path access in tool arguments | Behavioral Monitor | BEHAVIORAL | Critical |
| Phase transitions (sudden behavior change) | Behavioral Monitor | DRIFT | Critical |
| Base64 payload detection (embedded and standalone) | Entropy Analyzer | ENTROPY | Medium |
| Multiple base64 segment aggregation | Entropy Analyzer | ENTROPY | Medium |
| Steganographic C2 payloads | Entropy Analyzer | ENTROPY | Medium |
| Hidden instructions in tool responses | Entropy + Semantic | ENTROPY | High |
| Structural anomalies (unusual JSON depth) | Entropy Analyzer | ENTROPY | Low |
| Out-of-scope filesystem writes | Scope Enforcer | SCOPE-L4 | Critical |
| MCP config file modification | Scope Enforcer | SCOPE-L4 | Critical |
| Symlink escape attacks | Scope Enforcer | SCOPE-L4 | Critical |

## SMAC-L3 compliance

mcp-watchdog implements the SMAC (Structured MCP Audit Controls) Level 3 preprocessing standard:

- **SMAC-1**: Strip HTML comments, zero-width unicode (raw, JSON-escaped, HTML entities, URL-encoded, double-encoded), ANSI escape sequences, and bidirectional text overrides
- **SMAC-2**: Strip markdown reference links used for data exfiltration
- **SMAC-4**: Log all violations with content hashes and timestamps
- **SMAC-5**: Detect and strip `<IMPORTANT>` instruction blocks (with attributes, unclosed tags, homoglyph variants, HTML-encoded forms, split-line evasion), `[SYSTEM]`/`[ADMIN]`/`[ASSISTANT]` role injection (full line stripping), and credential-seeking patterns
- **SMAC-6**: Detect and redact leaked tokens/secrets (GitHub PATs, AWS keys, Slack tokens, JWTs, OpenAI keys, Stripe keys, Discord bot tokens, npm/PyPI tokens, Supabase, Sendgrid, Twilio, Vault, Datadog, Heroku, GCP service account keys, Azure connection strings, PEM private keys, unlabeled secret keys) with space-split evasion normalization

## Install

```bash
git clone https://github.com/bountyyfi/mcp-watchdog.git
cd mcp-watchdog
pip install -e ".[dev]"
```

With optional dependencies:

```bash
pip install -e ".[all]"    # Includes anthropic SDK + watchdog filesystem monitoring
pip install -e ".[semantic]"  # Just the LLM semantic classifier
pip install -e ".[filesystem]"  # Just filesystem monitoring
```

## Usage

Wrap any MCP server command with `mcp-watchdog --verbose --`. The original server command goes after `--`:

```bash
# Proxy mode — wrap an upstream MCP server:
mcp-watchdog --verbose -- npx -y @modelcontextprotocol/server-filesystem ~/projects

# Standalone scanner — pipe MCP messages through for testing:
echo '{"jsonrpc":"2.0","method":"tools/list"}' | mcp-watchdog
```

## Configuration

Replace your existing MCP server entry with mcp-watchdog + the original command as args after `--`.

### Claude Desktop

```json
{
  "mcpServers": {
    "filesystem-watchdog": {
      "command": "mcp-watchdog",
      "args": ["--verbose", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"],
      "env": {}
    }
  }
}
```

### Cursor / Windsurf

Same pattern — see `configs/` for IDE-specific examples.

## Live demo

See every detection layer fire in real time:

```bash
python demo.py
```

The demo starts a real proxy wrapping a fake MCP server, sends clean traffic and 7 different attack types through it, and shows what gets caught vs what passes through.

## Detection layers

### Layer 0: SMAC-L3 Preprocessing

Static pattern matching applied to every MCP response — `tools/call`, `resources/read`, `prompts/get`, `prompts/list`, `resources/list`, and `resources/templates/list`. Pre-normalization defeats split-line tag evasion and space-split token evasion before pattern matching. Strips injection patterns (including homoglyph, HTML-encoded, and role-injection variants), zero-width characters (raw, JSON-escaped, HTML entities, URL-encoded, double-encoded), ANSI escape sequences, bidirectional text overrides, hidden instructions, and redacts 30+ leaked token/secret patterns before they reach the AI model.

### Layer 1: Behavioral Drift Detection

Monitors MCP server behavior over time. Detects scope creep, behavioral fingerprinting, and phase transitions after establishing a baseline.

### Layer 2: Entropy + Semantic Analysis

Shannon entropy analysis detects base64-encoded payloads, instruction-like language, and structural anomalies. Optional LLM semantic classifier (Claude Haiku) catches steganographic payloads that are statistically normal but semantically malicious.

### Layer 3: Cross-Server Flow Tracking + Session Integrity

Tracks tokens (JWTs, UUIDs, prefixed API keys like `ghp_*`, `sk-*`, `AKIA*`) across servers to detect cross-server propagation. Monitors request/response message sequences to detect session smuggling and injected responses.

### Layer 4: Filesystem Scope Enforcement

Blocks writes to `.git/config`, `.ssh/`, `.aws/`, MCP config files via inotify/FSEvents monitoring. Resolves symlinks to prevent sandbox escape attacks.

### Layer 5: Tool Integrity + Shadow Detection

Hashes every tool definition on first load. Detects rug pulls (silent redefinition), tool removal, and schema changes. Scans parameter names for injection patterns that leak system prompts and conversation history. Detects tool shadowing (cross-server description pollution), name squatting (duplicate tool names), and preference manipulation (persuasive language biasing tool selection).

### Layer 6: Network Security + Injection Prevention

SSRF protection blocks requests to cloud metadata endpoints (AWS IMDS, GCP, Azure), localhost, and internal networks. Command injection scanner catches shell metacharacters and injection patterns in tool arguments — including Windows-specific vectors (`cmd.exe /c`, `powershell -enc`, `system32` shell paths). SQL injection scanner detects UNION SELECT, DROP TABLE, and boolean-based injection. Reverse shell detector catches bash /dev/tcp, nc -e, mkfifo, and Python socket/subprocess patterns.

### Layer 7: Supply Chain + Auth + Email

Typosquatting detection via Levenshtein distance against known-good server registry. OAuth flow validation catches malformed authorization endpoints (CVE-2025-6514), excessive scopes, and suspicious redirects. Token audience validation prevents replay attacks across servers (RFC 8707). Email header injection detector catches BCC exfiltration attacks (postmark-mcp style).

### Layer 8: Escalation + Response Integrity

False-error escalation detector catches fake error messages designed to trick AI into granting elevated access. Response content is scanned for patterns like "permission denied, need admin access" that manipulate the AI's decision-making.

### Layer 9: Rate Limiting + Notification Guard

Consent fatigue protection monitors tool call frequency per server. Detects both sustained flooding and burst patterns designed to desensitize user approval. Notification event injection detector catches rapid `notifications/tools/list_changed` and `notifications/resources/updated` events used to trigger rug pull re-fetches and resource re-reads.

### Layer 10: MCP Protocol Method Scanning (2025-11-25 spec)

Method-aware scanning for all MCP JSON-RPC methods:

- **`resources/read` responses**: Full SMAC + injection scanning on resource content (prompt injection via resource poisoning)
- **`resources/list` responses**: Description scanning for hidden instructions
- **`resources/templates/list` responses**: Template description scanning
- **`prompts/get` responses**: Message content scanning for injection in prompt templates
- **`prompts/list` responses**: Prompt description and argument schema scanning
- **`sampling/createMessage`**: Deep scanning of message array and `systemPrompt` for injection/exfiltration (not just presence alerting)
- **`elicitation/create`** (new in 2025-11-25): Credential harvesting detection — flags schemas requesting `password`, `token`, `api_key`, `secret`, `ssh_key`, etc. Scans message text for social engineering and SMAC injection
- **`initialize`**: Capability tracking for server and client feature declarations

## Running tests

```bash
# Full suite
pytest tests/ -v

# E2E only (starts real proxy subprocess)
pytest tests/test_e2e_proxy.py -v

# Unit/integration only
pytest tests/ -v --ignore=tests/test_e2e_proxy.py
```

273+ tests across unit, integration, and end-to-end suites.

**Unit tests** test each detection module in isolation. **Integration tests** test the `MCPWatchdogProxy` class across multi-server sequences. **End-to-end tests** start the actual proxy binary as a subprocess, connect it to a fake MCP server, and push real JSON-RPC traffic through stdin/stdout.

## Architecture

```
AI Assistant <-> mcp-watchdog proxy <-> MCP Server(s)
                      |
                      |-- SMAC-L3 preprocessor (token redaction + ANSI stripping)
                      |-- Entropy analyzer
                      |-- Behavioral monitor
                      |-- Flow tracker + session integrity (JWTs, UUIDs, API keys)
                      |-- Tool registry (rug pull detection)
                      |-- Tool shadow detector (shadowing + squatting)
                      |-- Parameter scanner
                      |-- URL filter (SSRF)
                      |-- Input sanitizer (cmd + SQL + reverse shell + Windows)
                      |-- Registry checker (supply chain)
                      |-- OAuth guard (+ token replay detection)
                      |-- Rate limiter (consent fatigue + notification injection)
                      |-- Email injection detector
                      |-- Escalation detector
                      |-- Semantic classifier (optional)
                      |-- Scope enforcer (filesystem + symlink)
                      |-- MCP method scanner:
                      |     resources/read, resources/list, prompts/get,
                      |     prompts/list, sampling/createMessage,
                      |     elicitation/create, initialize
                      +-- Capability tracker (server + client features)
```

mcp-watchdog is a transparent JSON-RPC proxy. It does not modify clean responses - only strips malicious content and raises alerts.

## Changelog

### 0.1.9

- **Tool Shadow hardening** — expanded override/replace instruction detection to catch `disregard`, `substitute`, `supersede`, `don't use the other`, and `use this instead of` patterns. CC field now checked alongside BCC for email header injection.
- **Email comma injection detection** — detects multiple recipients injected via commas in `to`, `cc`, `bcc`, and other recipient fields (e.g. `victim@example.com, attacker@evil.com`).
- **OAuth `javascript:`/`data:`/`vbscript:` URI blocking** — redirect URIs using dangerous schemes are now caught. Open redirect detection via query parameters (`redirect_url=`, `return_to=`, `next=`, etc.) added.
- **Behavioral monitor credential path access** — tool call arguments accessing `.ssh/`, `.aws/`, `.env`, `id_rsa`, `credentials.json`, `.kube/config`, etc. now trigger critical alerts. Wired into proxy request pipeline (was previously imported but never called).
- **Entropy analyzer base64 overhaul** — relaxed base64 validation (pad-tolerant, URL-safe variant support), regex-based chunk extraction finds base64 embedded in larger strings, and multiple small base64 segments are aggregated and flagged when total exceeds 32 chars.
- **Registry checker expansion** — allowlist expanded from 12 to 55+ known-good servers (official + widely-used community servers). Substring-based impersonation detection added. Unknown server alerts now include nearest known-good match with edit distance.
- **Rug pull sneaky tool addition** — new tools appearing after initial `tools/list` registration are now flagged as `tool_added` (previously only redefinition and removal were caught).
- **URL filter base64 exfil detection** — base64-encoded tokens in URL query parameters are decoded and checked against the full exfil pattern set. Added `sk-proj-`, `sk-ant-`, `rk_live_`, `rk_test_`, `xoxa-`, `xoxr-`, `sbp_`, `SharedAccessKey=` patterns.
- **273+ tests** (up from 263+).

### 0.1.7

- **Split-line tag evasion defense** — pre-normalization collapses whitespace within `<IMPORTANT>` tag names (`<IMPOR\nTANT>`, `<I M P O R T A N T>`) before pattern matching.
- **Space-split token evasion defense** — collapses spaces in known token prefixes (`sk_ live_` → `sk_live_`, `npm_ xxx` → `npm_xxx`) to prevent regex-bypass evasion.
- **`[SYSTEM]`/`[ADMIN]` full-line stripping** — role injection markers now strip the entire injected instruction, not just the `[SYSTEM]:` prefix.
- **Heroku labeled key detection** — catches `HEROKU_API_KEY=uuid` and `HEROKU_OAUTH_TOKEN=uuid` patterns without requiring "heroku" context word.
- **Unlabeled secret key detection** — catches `secret_key:`, `private_key:`, `secret_access_key=` with 30+ char values even without vendor-specific prefixes.
- **Discord bot token URL exfiltration** — added Discord bot token pattern to URL filter exfiltration scanner.
- **263+ tests** (up from 253+) — 10 new tests covering all evasion technique fixes.

### 0.1.6

- **26 security audit gap fixes** — comprehensive hardening across all detection layers.
- **SMAC-6 expanded to 30+ token patterns** — added Stripe (`sk_live_`, `sk_test_`, `rk_live_`, `rk_test_`), PEM private keys (RSA, EC, DSA, OPENSSH), Discord bot tokens, npm (`npm_`), PyPI (`pypi-`), Supabase (`sbp_`), Sendgrid (`SG.`), Twilio (`SK`), HashiCorp Vault (`hvs.`, `s.`), Datadog (`dd[ap]_`), Heroku UUIDs, GCP service account keys (`private_key_id`), and Azure connection strings (`AccountKey=`, `SharedAccessKey=`).
- **SMAC-5 bypass hardening** — catches `<IMPORTANT>` with HTML attributes, unclosed tags (to end-of-string), Unicode homoglyph variants (Greek Ι U+0399, Cyrillic І U+0406), HTML-encoded `&lt;IMPORTANT&gt;` tags, and `[SYSTEM]:`/`[ADMIN]:`/`[ASSISTANT]:` role injection markers.
- **SMAC-1 multi-encoding bypass fixes** — strips URL-encoded ZWSP (`%E2%80%8B`, `%E2%80%8C`, `%E2%80%8D`), double-encoded HTML entities (`&amp;#x200b;`, `&amp;#8203;`), and URL-encoded bidi overrides (`%E2%80%8E`, `%E2%80%8F`).
- **Input sanitizer improvements** — double-encoded path traversal detection (`..%252f`, `%2e%2e/`), reduced false positives on CSS (`color: red;`) and pipe-delimited data (`name|age|city`) by gating shell metacharacter detection on command context.
- **URL filter exfiltration expansion** — detects Stripe, npm, PyPI, Sendgrid, Vault, Datadog, Azure tokens and `api_key=`/`key=`/`credential=` parameters in URLs.
- **Stream buffer crash fix** — `sys.maxsize` StreamReader limit prevents proxy crash on large MCP responses (previously crashed on >64KB messages).
- **253+ tests** (up from 208+) — 45 new tests covering all audit gap fixes across 3 new/updated test files. (Now 263+ with 0.1.7 additions.)

### 0.1.5

- **MCP 2025-11-25 protocol coverage** — method-aware scanning for `resources/read`, `resources/list`, `resources/templates/list`, `prompts/get`, `prompts/list`, `sampling/createMessage` (deep scan), and `elicitation/create` (credential harvesting).
- **P0 bug fixes** — scope enforcer and semantic classifier were instantiated but never called in the proxy pipeline; symlink escape detection was dead code (compared `resolve()` to itself).
- **Elicitation credential harvesting** — detects `elicitation/create` requests with schemas requesting `password`, `token`, `api_key`, `secret`, `ssh_key`, `credit_card`, `ssn` fields.
- **Deep sampling scan** — `sampling/createMessage` now scans the full message array and `systemPrompt` for SMAC injection, not just alerting on method presence.
- **Cross-platform Windows support** — Windows command injection detection (`cmd.exe /c`, `powershell -enc`, system32 shell paths), OS-native path separators in scope enforcement, case-insensitive path matching on Windows, credential path regex matches both `/` and `\`.
- **Flow tracker improvements** — now extracts JWTs, UUIDs, and prefixed API keys (`ghp_*`, `sk-*`, `AKIA*`) for cross-server propagation detection.
- **Notification guard expanded** — `notifications/resources/updated` added to rate-limited notification set alongside `list_changed` types.
- **Removed unused dependencies** — `websockets`, `fastapi`, `uvicorn` removed from install requirements.
- **208+ tests** (up from 158) — 50 new tests across 9 new test files; all tests use `tmp_path` and `Path.home()` for cross-platform correctness. (Now 253+ with 0.1.6 additions.)

### 0.1.3

- **Fix SMAC corrupting non-filesystem servers** — SMAC regex patterns now run against individual JSON string values instead of the raw wire-format JSON, preventing corruption of structural characters (`{`, `}`, `"`, etc.) in legitimate responses. This fixes compatibility with resources, prompts, and other MCP server types beyond the filesystem server.
- **Windows support** — thread-based stdin reader replaces `connect_read_pipe` (unavailable on Windows `ProactorEventLoop`); signal handlers are now conditional on platform.

### 0.1.0

- Initial release with SMAC-L3, behavioral drift, entropy analysis, flow tracking, tool integrity, shadow detection, SSRF/injection prevention, supply chain checks, OAuth guard, rate limiting, and scope enforcement.

## License

MIT

## Credits

Open source by [Bountyy Oy](https://github.com/bountyyfi).

Research references:
- [Bountyy Oy - SMAC: Structured MCP Audit Controls](https://github.com/bountyyfi/invisible-prompt-injection/blob/main/SMAC.md)
- [Bountyy Oy - Thanatos MCP Attack Framework](https://github.com/bountyyfi/thanatos-mcp)
- [Bountyy Oy - ProjectMemory: MCP Parasite PoC](https://github.com/bountyyfi/ProjectMemory)
- [Invariant Labs - Tool Poisoning & Rug Pull Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [HiddenLayer - Parameter Injection](https://hiddenlayer.com/innovation-hub/exploiting-mcp-tool-parameters/)
- [BlueRock - MCP fURI SSRF](https://www.bluerock.io/post/mcp-furi-microsoft-markitdown-vulnerabilities)
- [Unit 42 - MCP Sampling Attacks](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Docker - MCP Supply Chain Horror Stories](https://www.docker.com/blog/mcp-horror-stories-the-supply-chain-attack/)
- [Elastic Security Labs - MCP Attack Vectors](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Pillar Security - MCP Risks](https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp)
- [Trail of Bits - Line Jumping Attack](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/)
- [Trail of Bits - mcp-context-protector](https://blog.trailofbits.com/2025/07/28/we-built-the-security-layer-mcp-always-needed/)
- [JFrog - Malicious MCP PyPI Reverse Shells](https://research.jfrog.com/post/3-malicious-mcps-pypi-reverse-shell/)
- [Snyk - Malicious postmark-mcp on npm](https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/)
- [Noma Security - Unicode Exploits in MCP](https://noma.security/blog/invisible-mcp-vulnerabilities-risks-exploits-in-the-ai-supply-chain/)
- [CoSAI - MCP Security White Paper](https://www.coalitionforsecureai.org/securing-the-ai-agent-revolution-a-practical-guide-to-mcp-security/)
- [MCPSecBench - Security Benchmark](https://arxiv.org/abs/2508.13220)
- [MCP-Guard - Defense Framework](https://arxiv.org/abs/2508.10991)
- [Breaking the Protocol - MCPSec](https://arxiv.org/abs/2601.17549)
- [CVE-2026-0755 - Gemini MCP Tool Command Injection](https://cybersecuritynews.com/gemini-mcp-tool-0-day-vulnerability/)
- [Invariant Labs - WhatsApp MCP Exfiltration](https://invariantlabs.ai/blog/whatsapp-mcp-exploited)
