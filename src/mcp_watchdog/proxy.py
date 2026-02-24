"""Core JSON-RPC proxy integrating all detection layers.

Intercepts MCP traffic and applies SMAC-L3 preprocessing,
entropy analysis, behavioral monitoring, cross-server flow tracking,
rug pull detection, parameter injection scanning, SSRF filtering,
command injection sanitization, supply chain verification,
token redaction, OAuth validation, session integrity checking,
scope enforcement, semantic classification, and per-server context isolation.
"""

import json
from typing import Any

from mcp_watchdog.smac import SMACPreprocessor, SMACViolation
from mcp_watchdog.entropy import EntropyAnalyzer
from mcp_watchdog.behavioral import BehavioralMonitor
from mcp_watchdog.flow_tracker import FlowTracker
from mcp_watchdog.tool_registry import ToolRegistry
from mcp_watchdog.param_scanner import ParamScanner
from mcp_watchdog.url_filter import URLFilter
from mcp_watchdog.input_sanitizer import InputSanitizer
from mcp_watchdog.registry_checker import RegistryChecker
from mcp_watchdog.oauth_guard import OAuthGuard
from mcp_watchdog.tool_shadow import ToolShadowDetector
from mcp_watchdog.rate_limiter import RateLimiter
from mcp_watchdog.scope import FilesystemScopeEnforcer
from mcp_watchdog.semantic import SemanticClassifier
from mcp_watchdog.alerts import WatchdogAlert, print_alert


class MCPWatchdogProxy:
    def __init__(self, verbose: bool = True) -> None:
        self.smac = SMACPreprocessor()
        self.entropy = EntropyAnalyzer()
        self.behavioral = BehavioralMonitor()
        self.flow = FlowTracker()
        self.tool_registry = ToolRegistry()
        self.param_scanner = ParamScanner()
        self.url_filter = URLFilter()
        self.input_sanitizer = InputSanitizer()
        self.registry_checker = RegistryChecker()
        self.oauth_guard = OAuthGuard()
        self.tool_shadow = ToolShadowDetector()
        self.rate_limiter = RateLimiter()
        self.semantic = SemanticClassifier()
        # Per-server scope enforcers keyed by server_id
        self._scope_enforcers: dict[str, FilesystemScopeEnforcer] = {}
        # Per-server context isolation (A10)
        self._server_contexts: dict[str, list[str]] = {}
        # Capabilities reported by each server from initialize response
        self._server_capabilities: dict[str, dict] = {}
        self.verbose = verbose

    def _emit(self, alert: WatchdogAlert, alerts: list[WatchdogAlert]) -> None:
        alerts.append(alert)
        if self.verbose:
            print_alert(alert)

    def set_scope(self, server_id: str, allowed_paths: list[str]) -> None:
        """Configure filesystem scope enforcement for a server."""
        self._scope_enforcers[server_id] = FilesystemScopeEnforcer(
            server_id, allowed_paths
        )

    def _smac_process_value(
        self, value: Any, server_id: str
    ) -> tuple[Any, list[SMACViolation]]:
        """Recursively apply SMAC to all string values in a JSON structure.

        This is JSON-structure-safe: regexes only run on individual string
        values, never across JSON keys/delimiters, so the JSON structure
        cannot be corrupted.
        """
        if isinstance(value, str):
            return self.smac.process(value, server_id)
        if isinstance(value, dict):
            violations: list[SMACViolation] = []
            out = {}
            for k, v in value.items():
                cleaned_v, v_violations = self._smac_process_value(v, server_id)
                out[k] = cleaned_v
                violations.extend(v_violations)
            return out, violations
        if isinstance(value, list):
            violations = []
            out_list = []
            for item in value:
                cleaned_item, item_violations = self._smac_process_value(
                    item, server_id
                )
                out_list.append(cleaned_item)
                violations.extend(item_violations)
            return out_list, violations
        return value, []

    def _smac_process_json(
        self, raw: str, server_id: str
    ) -> tuple[str, list[SMACViolation]]:
        """Apply SMAC preprocessing to JSON text values only.

        Parses the JSON first, then applies SMAC regexes to individual
        string values.  This prevents regex patterns from matching across
        JSON structural characters (quotes, braces, commas) which would
        corrupt the JSON and break downstream MCP clients.

        Falls back to raw-string processing for non-JSON messages.
        """
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return self.smac.process(raw, server_id)

        processed, violations = self._smac_process_value(data, server_id)
        return json.dumps(processed, ensure_ascii=False), violations

    def _scan_descriptions(
        self, items: list[dict], server_id: str, kind: str,
        alerts: list[WatchdogAlert],
    ) -> None:
        """Scan description fields on tools, resources, or prompts for injection."""
        for item in items:
            desc = item.get("description", "")
            if not desc:
                continue
            _, desc_violations = self.smac.process(desc, server_id)
            desc_entropy = self.entropy.analyze(
                json.dumps({"description": desc}), server_id
            )
            for v in desc_violations:
                self._emit(
                    WatchdogAlert(
                        severity="critical",
                        server_id=server_id,
                        rule=v.rule,
                        detail=f"{kind} description injection: {v.content_preview}",
                    ),
                    alerts,
                )
            for ea in desc_entropy:
                self._emit(
                    WatchdogAlert(
                        severity=ea.severity,
                        server_id=server_id,
                        rule="ENTROPY",
                        detail=f"{kind} description: {ea.detail}",
                    ),
                    alerts,
                )

    async def process_response(
        self, raw: str, server_id: str
    ) -> tuple[str, list[WatchdogAlert]]:
        all_alerts: list[WatchdogAlert] = []

        # SMAC-L3 preprocessing — JSON-aware so regexes never corrupt
        # the JSON structure (only individual string values are cleaned)
        cleaned, smac_violations = self._smac_process_json(raw, server_id)
        for v in smac_violations:
            self._emit(
                WatchdogAlert(
                    severity="critical" if v.rule == "SMAC-6" else "high",
                    server_id=server_id,
                    rule=v.rule,
                    detail=v.content_preview,
                ),
                all_alerts,
            )

        # Entropy analysis
        entropy_alerts = self.entropy.analyze(cleaned, server_id)
        for ea in entropy_alerts:
            self._emit(
                WatchdogAlert(
                    severity=ea.severity,
                    server_id=server_id,
                    rule="ENTROPY",
                    detail=ea.detail,
                ),
                all_alerts,
            )

        # SSRF + exfiltration detection in response content
        ssrf_alerts = self.url_filter.scan_content(cleaned, server_id)
        for sa in ssrf_alerts:
            rule = "EXFIL" if sa.reason == "url_exfiltration" else "SSRF"
            self._emit(
                WatchdogAlert(
                    severity=sa.severity,
                    server_id=server_id,
                    rule=rule,
                    detail=sa.detail,
                ),
                all_alerts,
            )

        # Cross-server flow tracking
        self.flow.record_response(server_id, cleaned)

        # Semantic analysis (optional, requires ANTHROPIC_API_KEY)
        sem_alerts = await self.semantic.analyze(cleaned, server_id)
        for sa in sem_alerts:
            self._emit(
                WatchdogAlert(
                    severity=sa.severity,
                    server_id=server_id,
                    rule="SEMANTIC",
                    detail=sa.detail,
                ),
                all_alerts,
            )

        # Parse JSON-RPC for structured checks
        try:
            parsed = json.loads(cleaned)
            request_id = parsed.get("id")
            result = parsed.get("result", {})

            # Session integrity check (A9)
            if request_id is not None:
                session_alerts = self.flow.check_response_integrity(
                    server_id, request_id, cleaned
                )
                for sa in session_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=sa.severity,
                            server_id=server_id,
                            rule="SESSION",
                            detail=sa.detail,
                        ),
                        all_alerts,
                    )

            # --- Capability tracking from initialize response ---
            if isinstance(result, dict) and "capabilities" in result:
                self._server_capabilities[server_id] = result["capabilities"]

            # --- Tool listing checks (tools/list response) ---
            if isinstance(result, dict) and "tools" in result:
                tools = result["tools"]

                # Rug pull detection (A1)
                rug_alerts = self.tool_registry.check_tools(
                    server_id, tools
                )
                for ra in rug_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=ra.severity,
                            server_id=server_id,
                            rule="RUG-PULL",
                            detail=ra.detail,
                        ),
                        all_alerts,
                    )

                # Parameter injection scan (A2)
                param_alerts = self.param_scanner.scan_tools(
                    server_id, tools
                )
                for pa in param_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=pa.severity,
                            server_id=server_id,
                            rule="PARAM-INJECT",
                            detail=pa.detail,
                        ),
                        all_alerts,
                    )

                # Tool shadowing / name squatting / preference manipulation
                shadow_alerts = self.tool_shadow.check_tools(
                    server_id, tools
                )
                for sha in shadow_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=sha.severity,
                            server_id=server_id,
                            rule="SHADOW",
                            detail=sha.detail,
                        ),
                        all_alerts,
                    )

                # Tool description injection scan
                self._scan_descriptions(tools, server_id, "Tool", all_alerts)

            # --- Resource listing checks (resources/list response) ---
            if isinstance(result, dict) and "resources" in result:
                resources = result["resources"]
                self._scan_descriptions(
                    resources, server_id, "Resource", all_alerts
                )

            # --- Resource templates (resources/templates/list response) ---
            if isinstance(result, dict) and "resourceTemplates" in result:
                templates = result["resourceTemplates"]
                self._scan_descriptions(
                    templates, server_id, "ResourceTemplate", all_alerts
                )

            # --- Prompt listing checks (prompts/list response) ---
            if isinstance(result, dict) and "prompts" in result:
                prompts = result["prompts"]
                self._scan_descriptions(
                    prompts, server_id, "Prompt", all_alerts
                )
                # Scan prompt argument schemas for injection
                for prompt in prompts:
                    args = prompt.get("arguments", [])
                    for arg in args:
                        arg_desc = arg.get("description", "")
                        if arg_desc:
                            _, dv = self.smac.process(arg_desc, server_id)
                            for v in dv:
                                self._emit(
                                    WatchdogAlert(
                                        severity="critical",
                                        server_id=server_id,
                                        rule=v.rule,
                                        detail=f"Prompt argument injection: {v.content_preview}",
                                    ),
                                    all_alerts,
                                )

            # --- Resource content checks (resources/read response) ---
            if isinstance(result, dict) and "contents" in result:
                for content_item in result["contents"]:
                    text = content_item.get("text", "")
                    if text:
                        # Check resource content for injection patterns
                        inj_alerts = self.input_sanitizer.scan_arguments(
                            server_id, "resource_content",
                            {"text": text},
                        )
                        for ia in inj_alerts:
                            rule = "CMD-INJECT"
                            if ia.reason == "sql_injection":
                                rule = "SQL-INJECT"
                            elif ia.reason == "reverse_shell":
                                rule = "REVERSE-SHELL"
                            self._emit(
                                WatchdogAlert(
                                    severity=ia.severity,
                                    server_id=server_id,
                                    rule=rule,
                                    detail=f"Resource content: {ia.detail}",
                                ),
                                all_alerts,
                            )

            # --- Scope enforcement on file paths in responses ---
            if server_id in self._scope_enforcers:
                enforcer = self._scope_enforcers[server_id]
                # Check tool call results that reference file paths
                if isinstance(result, dict):
                    for key in ("path", "file", "filename", "uri"):
                        path_val = result.get(key)
                        if isinstance(path_val, str) and path_val:
                            violation = enforcer.check_write(path_val)
                            if violation:
                                self._emit(
                                    WatchdogAlert(
                                        severity=violation.severity,
                                        server_id=server_id,
                                        rule="SCOPE-L4",
                                        detail=f"Out-of-scope path: {path_val}",
                                    ),
                                    all_alerts,
                                )

            # --- Prompt content checks (prompts/get response) ---
            # The result has a "messages" array with role/content pairs
            if isinstance(result, dict) and "messages" in result:
                for pm in result["messages"]:
                    content = pm.get("content", {})
                    # content can be a string or {"type":"text","text":"..."}
                    text = ""
                    if isinstance(content, str):
                        text = content
                    elif isinstance(content, dict):
                        text = content.get("text", "")
                    if text:
                        _, pv = self.smac.process(text, server_id)
                        for v in pv:
                            self._emit(
                                WatchdogAlert(
                                    severity="critical",
                                    server_id=server_id,
                                    rule=v.rule,
                                    detail=f"Prompt message injection: {v.content_preview}",
                                ),
                                all_alerts,
                            )
                        # Check for injection patterns in prompt content
                        pm_inj = self.input_sanitizer.scan_arguments(
                            server_id, "prompt_content", {"text": text},
                        )
                        for ia in pm_inj:
                            rule = "CMD-INJECT"
                            if ia.reason == "sql_injection":
                                rule = "SQL-INJECT"
                            elif ia.reason == "reverse_shell":
                                rule = "REVERSE-SHELL"
                            self._emit(
                                WatchdogAlert(
                                    severity=ia.severity,
                                    server_id=server_id,
                                    rule=rule,
                                    detail=f"Prompt content: {ia.detail}",
                                ),
                                all_alerts,
                            )

            method = parsed.get("method", "")
            params = parsed.get("params", {})

            # --- Sampling deep scan (A4) ---
            # Server-initiated sampling/createMessage is a direct LLM control vector
            if method == "sampling/createMessage":
                self._emit(
                    WatchdogAlert(
                        severity="high",
                        server_id=server_id,
                        rule="SAMPLING",
                        detail="Server initiated sampling/createMessage request",
                    ),
                    all_alerts,
                )
                # Deep-scan the message content for injection
                if isinstance(params, dict):
                    messages = params.get("messages", [])
                    for sm in messages:
                        content = sm.get("content", {})
                        text = ""
                        if isinstance(content, str):
                            text = content
                        elif isinstance(content, dict):
                            text = content.get("text", "")
                        if text:
                            _, sv = self.smac.process(text, server_id)
                            for v in sv:
                                self._emit(
                                    WatchdogAlert(
                                        severity="critical",
                                        server_id=server_id,
                                        rule=v.rule,
                                        detail=f"Sampling message injection: {v.content_preview}",
                                    ),
                                    all_alerts,
                                )
                    # Scan system prompt if present
                    sys_prompt = params.get("systemPrompt", "")
                    if sys_prompt:
                        _, spv = self.smac.process(sys_prompt, server_id)
                        for v in spv:
                            self._emit(
                                WatchdogAlert(
                                    severity="critical",
                                    server_id=server_id,
                                    rule=v.rule,
                                    detail=f"Sampling system prompt injection: {v.content_preview}",
                                ),
                                all_alerts,
                            )

            # --- Elicitation scanning (2025-11-25 spec) ---
            # Server asks client to collect user input — phishing/credential harvesting vector
            if method == "elicitation/create":
                self._emit(
                    WatchdogAlert(
                        severity="high",
                        server_id=server_id,
                        rule="ELICITATION",
                        detail="Server initiated elicitation/create request",
                    ),
                    all_alerts,
                )
                if isinstance(params, dict):
                    # Check message for social engineering
                    elicit_msg = params.get("message", "")
                    if elicit_msg:
                        _, ev = self.smac.process(elicit_msg, server_id)
                        for v in ev:
                            self._emit(
                                WatchdogAlert(
                                    severity="critical",
                                    server_id=server_id,
                                    rule=v.rule,
                                    detail=f"Elicitation message injection: {v.content_preview}",
                                ),
                                all_alerts,
                            )
                    # Check schema for credential-harvesting field names
                    schema = params.get("requestedSchema", {})
                    if isinstance(schema, dict):
                        props = schema.get("properties", {})
                        SENSITIVE_ELICIT_FIELDS = {
                            "password", "token", "api_key", "secret",
                            "credential", "private_key", "access_token",
                            "ssh_key", "credit_card", "ssn",
                        }
                        for field_name in props:
                            if field_name.lower() in SENSITIVE_ELICIT_FIELDS:
                                self._emit(
                                    WatchdogAlert(
                                        severity="critical",
                                        server_id=server_id,
                                        rule="ELICITATION",
                                        detail=f"Credential harvesting: elicitation requests '{field_name}' field",
                                    ),
                                    all_alerts,
                                )

            # Notification event injection check (all notification types)
            if method.startswith("notifications/"):
                notif_alerts = self.rate_limiter.check_notification(
                    server_id, method
                )
                for na in notif_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=na.severity,
                            server_id=server_id,
                            rule="NOTIF-INJECT",
                            detail=na.detail,
                        ),
                        all_alerts,
                    )

        except (json.JSONDecodeError, AttributeError):
            pass

        # False-error escalation check on response content
        escalation_alerts = self.tool_shadow.check_response_for_escalation(
            server_id, cleaned
        )
        for esc in escalation_alerts:
            self._emit(
                WatchdogAlert(
                    severity=esc.severity,
                    server_id=server_id,
                    rule="ESCALATION",
                    detail=esc.detail,
                ),
                all_alerts,
            )

        # Context isolation (A10) - track per-server
        if server_id not in self._server_contexts:
            self._server_contexts[server_id] = []
        self._server_contexts[server_id].append(cleaned[:200])

        return cleaned, all_alerts

    async def process_request(
        self, raw: str, server_id: str
    ) -> tuple[str, list[WatchdogAlert]]:
        all_alerts: list[WatchdogAlert] = []

        # Cross-server flow check
        flow_alerts = self.flow.record_request(server_id, raw)
        for fa in flow_alerts:
            self._emit(
                WatchdogAlert(
                    severity=fa.severity,
                    server_id=server_id,
                    rule="CROSS-SERVER",
                    detail=f"Data from {fa.source_server} -> {fa.target_server}: {fa.token_preview}",
                ),
                all_alerts,
            )

        # SSRF + exfiltration check on outgoing requests
        ssrf_alerts = self.url_filter.scan_content(raw, server_id)
        for sa in ssrf_alerts:
            rule = "EXFIL" if sa.reason == "url_exfiltration" else "SSRF"
            self._emit(
                WatchdogAlert(
                    severity=sa.severity,
                    server_id=server_id,
                    rule=rule,
                    detail=sa.detail,
                ),
                all_alerts,
            )

        # Parse for tool call arguments
        try:
            parsed = json.loads(raw)
            request_id = parsed.get("id")
            method = parsed.get("method", "")
            params = parsed.get("params", {})

            # Track request for session integrity (A9)
            if request_id is not None:
                self.flow.track_request(server_id, request_id, raw)

            # Rate limiting / consent fatigue check
            if method == "tools/call":
                rate_alerts = self.rate_limiter.record_tool_call(server_id)
                for ra in rate_alerts:
                    self._emit(
                        WatchdogAlert(
                            severity=ra.severity,
                            server_id=server_id,
                            rule="RATE-LIMIT",
                            detail=ra.detail,
                        ),
                        all_alerts,
                    )

            # Command injection scan on tool call arguments (A5)
            if method == "tools/call":
                tool_name = params.get("name", "unknown")
                arguments = params.get("arguments", {})
                if isinstance(arguments, dict):
                    inj_alerts = self.input_sanitizer.scan_arguments(
                        server_id, tool_name, arguments
                    )
                    for ia in inj_alerts:
                        rule = "CMD-INJECT"
                        if ia.reason == "sql_injection":
                            rule = "SQL-INJECT"
                        elif ia.reason == "reverse_shell":
                            rule = "REVERSE-SHELL"
                        self._emit(
                            WatchdogAlert(
                                severity=ia.severity,
                                server_id=server_id,
                                rule=rule,
                                detail=ia.detail,
                            ),
                            all_alerts,
                        )

                    # Behavioral monitor - credential path access check
                    beh_alerts = self.behavioral.check_request_params(
                        server_id, tool_name, arguments
                    )
                    for ba in beh_alerts:
                        self._emit(
                            WatchdogAlert(
                                severity=ba.severity,
                                server_id=server_id,
                                rule="BEHAVIORAL",
                                detail=ba.detail,
                            ),
                            all_alerts,
                        )

                    # Email header injection check
                    email_alerts = self.tool_shadow.check_email_injection(
                        server_id, tool_name, arguments
                    )
                    for ema in email_alerts:
                        self._emit(
                            WatchdogAlert(
                                severity=ema.severity,
                                server_id=server_id,
                                rule="EMAIL-INJECT",
                                detail=ema.detail,
                            ),
                            all_alerts,
                        )

                    # Scope enforcement on file path arguments
                    if server_id in self._scope_enforcers:
                        enforcer = self._scope_enforcers[server_id]
                        for key in ("path", "file", "filename", "uri", "destination"):
                            path_val = arguments.get(key)
                            if isinstance(path_val, str) and path_val:
                                violation = enforcer.check_write(path_val)
                                if violation:
                                    self._emit(
                                        WatchdogAlert(
                                            severity=violation.severity,
                                            server_id=server_id,
                                            rule="SCOPE-L4",
                                            detail=f"Out-of-scope write: {path_val}",
                                        ),
                                        all_alerts,
                                    )

            # Context isolation check (A10)
            if method == "tools/call" and params.get("arguments"):
                args_str = json.dumps(params["arguments"])
                for other_id, ctx_list in self._server_contexts.items():
                    if other_id == server_id:
                        continue
                    for ctx in ctx_list:
                        if len(ctx) > 30 and ctx[:30] in args_str:
                            self._emit(
                                WatchdogAlert(
                                    severity="high",
                                    server_id=server_id,
                                    rule="CONTEXT-LEAK",
                                    detail=f"Context from {other_id} leaked into {server_id} tool call",
                                ),
                                all_alerts,
                            )

        except (json.JSONDecodeError, AttributeError):
            pass

        return raw, all_alerts

    def check_server_registration(
        self, server_name: str
    ) -> list[WatchdogAlert]:
        """Check server name against supply chain registry (A6)."""
        alerts: list[WatchdogAlert] = []
        sc_alerts = self.registry_checker.check_server(server_name)
        for sca in sc_alerts:
            self._emit(
                WatchdogAlert(
                    severity=sca.severity,
                    server_id=server_name,
                    rule="SUPPLY-CHAIN",
                    detail=sca.detail,
                ),
                alerts,
            )
        return alerts

    def check_oauth(
        self,
        server_id: str,
        client_id: str | None = None,
        redirect_uri: str | None = None,
        scopes: list[str] | None = None,
        authorization_endpoint: str | None = None,
    ) -> list[WatchdogAlert]:
        """Check OAuth flow for confused deputy attacks (A8)."""
        alerts: list[WatchdogAlert] = []
        oauth_alerts = self.oauth_guard.check_auth_request(
            server_id=server_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            authorization_endpoint=authorization_endpoint,
        )
        for oa in oauth_alerts:
            self._emit(
                WatchdogAlert(
                    severity=oa.severity,
                    server_id=server_id,
                    rule="OAUTH",
                    detail=oa.detail,
                ),
                alerts,
            )
        return alerts

    def check_token_audience(
        self,
        server_id: str,
        token_audience: str | None = None,
        token_issuer: str | None = None,
    ) -> list[WatchdogAlert]:
        """Check for token replay / audience mismatch (RFC 8707)."""
        alerts: list[WatchdogAlert] = []
        aud_alerts = self.oauth_guard.check_token_audience(
            server_id=server_id,
            token_audience=token_audience,
            token_issuer=token_issuer,
        )
        for aa in aud_alerts:
            self._emit(
                WatchdogAlert(
                    severity=aa.severity,
                    server_id=server_id,
                    rule="TOKEN-REPLAY",
                    detail=aa.detail,
                ),
                alerts,
            )
        return alerts
