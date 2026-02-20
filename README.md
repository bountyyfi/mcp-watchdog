# mcp-watchdog

MCP security proxy that sits between AI coding assistants and MCP servers, detecting and blocking known MCP attack classes.

Catches **MCP Parasite**, **Thanatos** (all 4 layers), and **SANDWORM_MODE**-style prompt injection before it reaches your AI assistant.

## Why this exists

MCP (Model Context Protocol) servers have full access to your AI assistant's context. A malicious or compromised server can:

- **Inject hidden instructions** into tool descriptions (`<IMPORTANT>` blocks telling the AI to exfiltrate credentials)
- **Profile your behavior** by collecting commit timestamps, deploy windows, and activity patterns
- **Encode payloads steganographically** inside normal-looking JSON responses
- **Propagate across servers** — output from Server A influences calls to Server B
- **Persist across sessions** by writing state to project files outside declared scope

mcp-watchdog intercepts all JSON-RPC traffic and applies multi-layer detection before any data reaches your AI model.

## What it catches

| Attack Class | Detection Layer | Severity |
|---|---|---|
| SANDWORM_MODE `<IMPORTANT>` injection | SMAC-5 | Critical |
| HTML comment injection | SMAC-1 | High |
| Zero-width unicode steganography | SMAC-1 | High |
| Markdown reference link exfiltration | SMAC-2 | High |
| Credential-seeking patterns | SMAC-5 | Critical |
| Behavioral fingerprinting (commit rhythms, deploy patterns) | Behavioral drift | High |
| Scope creep (requesting credential fields) | Behavioral drift | Critical |
| Phase transitions (sudden behavior change) | Behavioral drift | Critical |
| Steganographic C2 payloads | Entropy analysis | Medium |
| Hidden instructions in tool responses | Entropy analysis + Semantic classifier | High |
| Cross-server data propagation | Flow tracker | High |
| Cross-server manipulation instructions | Entropy analysis | High |
| Out-of-scope filesystem writes | Scope enforcer | Critical |
| MCP config file modification | Scope enforcer | Critical |

## SMAC-L3 compliance

mcp-watchdog implements the SMAC (Structured MCP Audit Controls) Level 3 preprocessing standard:

- **SMAC-1**: Strip HTML comments and zero-width unicode characters
- **SMAC-2**: Strip markdown reference links used for data exfiltration
- **SMAC-4**: Log all violations with content hashes and timestamps
- **SMAC-5**: Detect and strip `<IMPORTANT>` instruction blocks and credential-seeking patterns

## Install

```bash
pip install mcp-watchdog
```

For development:

```bash
git clone https://github.com/bountyyfi/mcp-watchdog.git
cd mcp-watchdog
pip install -e ".[dev]"
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

Static pattern matching applied to every tool response before it reaches the AI model. Strips known injection patterns, zero-width characters, and hidden instructions.

### Layer 1: Behavioral Drift Detection

Monitors MCP server behavior over time. Detects scope creep (requesting credential fields), behavioral fingerprinting (collecting user activity patterns), and phase transitions (sudden behavior changes after establishing a normal baseline).

### Layer 2: Entropy + Semantic Analysis

Shannon entropy analysis detects base64-encoded payloads and high-entropy strings hidden in normal-looking responses. Optional LLM semantic classifier (Claude Haiku) catches steganographic payloads that are statistically normal but semantically malicious.

### Layer 3: Cross-Server Flow Tracking

Tracks significant tokens from each server's responses. Flags when data from one server appears in requests to another server — the signature of cross-server propagation attacks.

### Layer 4: Filesystem Scope Enforcement

Monitors filesystem writes by MCP server processes. Flags writes outside declared scope, writes to `.git/config`, `.ssh/`, `.aws/`, MCP config files, and other sensitive locations.

## Running tests

```bash
pytest tests/ -v
```

## Architecture

```
AI Assistant <-> mcp-watchdog proxy <-> MCP Server(s)
                      |
                      ├── SMAC-L3 preprocessor
                      ├── Entropy analyzer
                      ├── Behavioral monitor
                      ├── Flow tracker
                      ├── Semantic classifier (optional)
                      └── Scope enforcer
```

mcp-watchdog is a transparent JSON-RPC proxy. It does not modify clean responses — only strips malicious content and raises alerts.

## License

MIT

## Credits

Open source by [Bountyy Oy](https://github.com/bountyyfi).

Research references:
- MCP Parasite attack class
- Thanatos multi-layer MCP attack framework
- SANDWORM_MODE prompt injection via tool descriptions
- SMAC (Structured MCP Audit Controls) standard
