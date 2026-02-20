# mcp-watchdog

MCP security proxy that sits between AI coding assistants and MCP servers, detecting and blocking all known MCP attack classes.

Catches **Rug Pulls**, **Tool Poisoning**, **Parameter Injection**, **SSRF**, **Command Injection**, **Supply Chain Impersonation**, **Token Leakage**, **OAuth Confused Deputy**, **Session Smuggling**, **Context Leakage**, **MCP Parasite**, **Thanatos** (all 4 layers), and **SANDWORM_MODE**-style prompt injection — before any of it reaches your AI assistant.

## Why this exists

MCP (Model Context Protocol) servers have full access to your AI assistant's context. A malicious or compromised server can:

- **Inject hidden instructions** into tool descriptions (`<IMPORTANT>` blocks telling the AI to exfiltrate credentials)
- **Silently redefine tools** after initial approval (Rug Pull attacks)
- **Steal system prompts and conversation history** via parameter injection (HiddenLayer attack)
- **Access cloud metadata** via SSRF through URI parameters (MCP fURI, 36.7% of servers vulnerable)
- **Execute arbitrary commands** via shell metacharacters in tool arguments
- **Impersonate legitimate packages** via typosquatting (fake Postmark MCP server)
- **Leak API keys and tokens** (GitHub PATs, AWS keys, Slack tokens, JWTs) in responses
- **Hijack OAuth flows** via malformed authorization endpoints (CVE-2025-6514)
- **Inject messages into sessions** via agent session smuggling (A2A attacks)
- **Profile your behavior** by collecting commit timestamps, deploy windows, and activity patterns
- **Encode payloads steganographically** inside normal-looking JSON responses
- **Propagate across servers** — output from Server A influences calls to Server B
- **Persist across sessions** by writing state to project files outside declared scope

mcp-watchdog intercepts all JSON-RPC traffic and applies multi-layer detection before any data reaches your AI model.

## What it catches

| Attack Class | Detection Layer | Rule | Severity |
|---|---|---|---|
| SANDWORM_MODE `<IMPORTANT>` injection | SMAC-L3 | SMAC-5 | Critical |
| HTML comment injection | SMAC-L3 | SMAC-1 | High |
| Zero-width unicode steganography | SMAC-L3 | SMAC-1 | High |
| Markdown reference link exfiltration | SMAC-L3 | SMAC-2 | High |
| Credential-seeking patterns | SMAC-L3 | SMAC-5 | Critical |
| Token/secret leakage (GitHub, AWS, Slack, JWT, OpenAI) | SMAC-L3 | SMAC-6 | Critical |
| Rug Pull (silent tool redefinition) | Tool Registry | RUG-PULL | Critical |
| Tool removal after establishing trust | Tool Registry | RUG-PULL | High |
| Parameter injection (`system_prompt`, `conversation_history`) | Param Scanner | PARAM-INJECT | Critical |
| Suspicious parameter patterns | Param Scanner | PARAM-INJECT | High |
| SSRF to cloud metadata (AWS/GCP/Azure IMDS) | URL Filter | SSRF | Critical |
| SSRF to localhost / internal networks | URL Filter | SSRF | High |
| Shell metacharacter injection | Input Sanitizer | CMD-INJECT | Critical |
| Command injection patterns | Input Sanitizer | CMD-INJECT | Critical |
| Path traversal attacks | Input Sanitizer | CMD-INJECT | High |
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

## SMAC-L3 compliance

mcp-watchdog implements the SMAC (Structured MCP Audit Controls) Level 3 preprocessing standard:

- **SMAC-1**: Strip HTML comments and zero-width unicode characters
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

Static pattern matching applied to every tool response. Strips injection patterns, zero-width characters, hidden instructions, and redacts leaked tokens/secrets before they reach the AI model.

### Layer 1: Behavioral Drift Detection

Monitors MCP server behavior over time. Detects scope creep, behavioral fingerprinting, and phase transitions after establishing a baseline.

### Layer 2: Entropy + Semantic Analysis

Shannon entropy analysis detects base64-encoded payloads, instruction-like language, and structural anomalies. Optional LLM semantic classifier (Claude Haiku) catches steganographic payloads that are statistically normal but semantically malicious.

### Layer 3: Cross-Server Flow Tracking + Session Integrity

Tracks tokens across servers to detect cross-server propagation. Monitors request/response message sequences to detect session smuggling and injected responses.

### Layer 4: Filesystem Scope Enforcement

Blocks writes to `.git/config`, `.ssh/`, `.aws/`, MCP config files via inotify/FSEvents monitoring.

### Layer 5: Tool Integrity

Hashes every tool definition on first load. Detects rug pulls (silent redefinition), tool removal, and schema changes. Scans parameter names for injection patterns that leak system prompts and conversation history.

### Layer 6: Network Security

SSRF protection blocks requests to cloud metadata endpoints (AWS IMDS, GCP, Azure), localhost, and internal networks. Command injection scanner catches shell metacharacters and injection patterns in tool arguments.

### Layer 7: Supply Chain + Auth

Typosquatting detection via Levenshtein distance against known-good server registry. OAuth flow validation catches malformed authorization endpoints (CVE-2025-6514), excessive scopes, and suspicious redirects.

## Running tests

```bash
pytest tests/ -v
```

80 tests covering all detection modules.

## Architecture

```
AI Assistant <-> mcp-watchdog proxy <-> MCP Server(s)
                      |
                      ├── SMAC-L3 preprocessor (token redaction)
                      ├── Entropy analyzer
                      ├── Behavioral monitor
                      ├── Flow tracker + session integrity
                      ├── Tool registry (rug pull detection)
                      ├── Parameter scanner
                      ├── URL filter (SSRF)
                      ├── Input sanitizer (command injection)
                      ├── Registry checker (supply chain)
                      ├── OAuth guard
                      ├── Semantic classifier (optional)
                      └── Scope enforcer (filesystem)
```

mcp-watchdog is a transparent JSON-RPC proxy. It does not modify clean responses — only strips malicious content and raises alerts.

## License

MIT

## Credits

Open source by [Bountyy Oy](https://github.com/bountyyfi).

Research references:
- [Invariant Labs — Tool Poisoning & Rug Pull Attacks](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [HiddenLayer — Parameter Injection](https://hiddenlayer.com/innovation-hub/exploiting-mcp-tool-parameters/)
- [BlueRock — MCP fURI SSRF](https://www.bluerock.io/post/mcp-furi-microsoft-markitdown-vulnerabilities)
- [Unit 42 — MCP Sampling Attacks](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Docker — MCP Supply Chain Horror Stories](https://www.docker.com/blog/mcp-horror-stories-the-supply-chain-attack/)
- [Elastic Security Labs — MCP Attack Vectors](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)
- [Pillar Security — MCP Risks](https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp)
