# mcp-watchdog

MCP security proxy that sits between AI coding assistants and MCP servers, detecting and blocking all known MCP attack classes.

Catches **Rug Pulls**, **Tool Poisoning**, **Tool Shadowing**, **Name Squatting**, **Parameter Injection**, **SSRF**, **Command Injection**, **SQL Injection**, **Reverse Shell**, **Supply Chain Impersonation**, **Token Leakage**, **OAuth Confused Deputy**, **Session Smuggling**, **Context Leakage**, **Email Header Injection**, **False-Error Escalation**, **Preference Manipulation**, **ANSI Escape Injection**, **MCP Parasite**, **Thanatos** (all 4 layers), and **SANDWORM_MODE**-style prompt injection - before any of it reaches your AI assistant.

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
| Token/secret leakage (GitHub, AWS, Slack, JWT, OpenAI) | SMAC-L3 | SMAC-6 | Critical |
| Rug Pull (silent tool redefinition) | Tool Registry | RUG-PULL | Critical |
| Tool removal after establishing trust | Tool Registry | RUG-PULL | High |
| Tool Shadowing (cross-server desc pollution) | Tool Shadow | SHADOW | Critical |
| Tool Name Squatting (duplicate names across servers) | Tool Shadow | SHADOW | Critical |
| Preference Manipulation (biasing tool selection) | Tool Shadow | SHADOW | High |
| Cross-server tool reference in descriptions | Tool Shadow | SHADOW | High |
| Parameter injection (`system_prompt`, `conversation_history`) | Param Scanner | PARAM-INJECT | Critical |
| Suspicious parameter patterns | Param Scanner | PARAM-INJECT | High |
| SSRF to cloud metadata (AWS/GCP/Azure IMDS) | URL Filter | SSRF | Critical |
| SSRF to localhost / internal networks | URL Filter | SSRF | High |
| Shell metacharacter injection | Input Sanitizer | CMD-INJECT | Critical |
| Command injection patterns | Input Sanitizer | CMD-INJECT | Critical |
| Path traversal attacks | Input Sanitizer | CMD-INJECT | High |
| SQL injection (UNION SELECT, DROP TABLE, etc.) | Input Sanitizer | SQL-INJECT | Critical |
| Reverse shell patterns (bash /dev/tcp, nc -e, mkfifo) | Input Sanitizer | REVERSE-SHELL | Critical |
| Email header injection (BCC exfiltration) | Tool Shadow | EMAIL-INJECT | Critical |
| False-error escalation (fake errors triggering privilege escalation) | Tool Shadow | ESCALATION | High |
| Supply chain typosquatting | Registry Checker | SUPPLY-CHAIN | Critical |
| Known malicious server patterns | Registry Checker | SUPPLY-CHAIN | Critical |
| OAuth authorization endpoint injection (CVE-2025-6514) | OAuth Guard | OAUTH | Critical |
| Excessive OAuth scope requests | OAuth Guard | OAUTH | High |
| Suspicious OAuth redirect URIs | OAuth Guard | OAUTH | Critical |
| MCP sampling exploitation | Proxy | SAMPLING | High |
| Session smuggling (orphaned/injected responses) | Flow Tracker | SESSION | Critical |
| Cross-server data propagation | Flow Tracker | CROSS-SERVER | High |
| Context leakage between servers | Proxy | CONTEXT-LEAK | High |
| Behavioral fingerprinting | Behavioral Monitor | DRIFT | High |
| Scope creep (credential field access) | Behavioral Monitor | DRIFT | Critical |
| Phase transitions (sudden behavior change) | Behavioral Monitor | DRIFT | Critical |
| Steganographic C2 payloads | Entropy Analyzer | ENTROPY | Medium |
| Hidden instructions in tool responses | Entropy + Semantic | ENTROPY | High |
| Structural anomalies (unusual JSON depth) | Entropy Analyzer | ENTROPY | Low |
| Out-of-scope filesystem writes | Scope Enforcer | SCOPE-L4 | Critical |
| MCP config file modification | Scope Enforcer | SCOPE-L4 | Critical |
| Symlink escape attacks | Scope Enforcer | SCOPE-L4 | Critical |

## SMAC-L3 compliance

mcp-watchdog implements the SMAC (Structured MCP Audit Controls) Level 3 preprocessing standard:

- **SMAC-1**: Strip HTML comments, zero-width unicode, ANSI escape sequences, and bidirectional text overrides
- **SMAC-2**: Strip markdown reference links used for data exfiltration
- **SMAC-4**: Log all violations with content hashes and timestamps
- **SMAC-5**: Detect and strip `<IMPORTANT>` instruction blocks and credential-seeking patterns
- **SMAC-6**: Detect and redact leaked tokens/secrets (GitHub PATs, AWS keys, Slack tokens, JWTs, OpenAI keys)

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

## Configuration

Change one line in your AI assistant's MCP config to route traffic through mcp-watchdog.

### Claude Desktop

```json
{
  "mcpServers": {
    "mcp-watchdog": {
      "command": "mcp-watchdog",
      "args": ["--verbose"],
      "env": {}
    }
  }
}
```

See `configs/` for Cursor and Windsurf examples.

## Detection layers

### Layer 0: SMAC-L3 Preprocessing

Static pattern matching applied to every tool response. Strips injection patterns, zero-width characters, ANSI escape sequences, bidirectional text overrides, hidden instructions, and redacts leaked tokens/secrets before they reach the AI model.

### Layer 1: Behavioral Drift Detection

Monitors MCP server behavior over time. Detects scope creep, behavioral fingerprinting, and phase transitions after establishing a baseline.

### Layer 2: Entropy + Semantic Analysis

Shannon entropy analysis detects base64-encoded payloads, instruction-like language, and structural anomalies. Optional LLM semantic classifier (Claude Haiku) catches steganographic payloads that are statistically normal but semantically malicious.

### Layer 3: Cross-Server Flow Tracking + Session Integrity

Tracks tokens across servers to detect cross-server propagation. Monitors request/response message sequences to detect session smuggling and injected responses.

### Layer 4: Filesystem Scope Enforcement

Blocks writes to `.git/config`, `.ssh/`, `.aws/`, MCP config files via inotify/FSEvents monitoring. Resolves symlinks to prevent sandbox escape attacks.

### Layer 5: Tool Integrity + Shadow Detection

Hashes every tool definition on first load. Detects rug pulls (silent redefinition), tool removal, and schema changes. Scans parameter names for injection patterns that leak system prompts and conversation history. Detects tool shadowing (cross-server description pollution), name squatting (duplicate tool names), and preference manipulation (persuasive language biasing tool selection).

### Layer 6: Network Security + Injection Prevention

SSRF protection blocks requests to cloud metadata endpoints (AWS IMDS, GCP, Azure), localhost, and internal networks. Command injection scanner catches shell metacharacters and injection patterns in tool arguments. SQL injection scanner detects UNION SELECT, DROP TABLE, and boolean-based injection. Reverse shell detector catches bash /dev/tcp, nc -e, mkfifo, and Python socket/subprocess patterns.

### Layer 7: Supply Chain + Auth + Email

Typosquatting detection via Levenshtein distance against known-good server registry. OAuth flow validation catches malformed authorization endpoints (CVE-2025-6514), excessive scopes, and suspicious redirects. Email header injection detector catches BCC exfiltration attacks (postmark-mcp style).

### Layer 8: Escalation + Response Integrity

False-error escalation detector catches fake error messages designed to trick AI into granting elevated access. Response content is scanned for patterns like "permission denied, need admin access" that manipulate the AI's decision-making.

## Running tests

```bash
pytest tests/ -v
```

111 tests covering all detection modules.

## Architecture

```
AI Assistant <-> mcp-watchdog proxy <-> MCP Server(s)
                      |
                      |-- SMAC-L3 preprocessor (token redaction + ANSI stripping)
                      |-- Entropy analyzer
                      |-- Behavioral monitor
                      |-- Flow tracker + session integrity
                      |-- Tool registry (rug pull detection)
                      |-- Tool shadow detector (shadowing + squatting)
                      |-- Parameter scanner
                      |-- URL filter (SSRF)
                      |-- Input sanitizer (cmd + SQL + reverse shell)
                      |-- Registry checker (supply chain)
                      |-- OAuth guard
                      |-- Email injection detector
                      |-- Escalation detector
                      |-- Semantic classifier (optional)
                      +-- Scope enforcer (filesystem + symlink)
```

mcp-watchdog is a transparent JSON-RPC proxy. It does not modify clean responses - only strips malicious content and raises alerts.

## License

MIT

## Credits

Open source by [Bountyy Oy](https://github.com/bountyyfi).

Research references:
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
