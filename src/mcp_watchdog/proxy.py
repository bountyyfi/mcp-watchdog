"""Core JSON-RPC proxy integrating all detection layers.

Intercepts MCP traffic and applies SMAC-L3 preprocessing,
entropy analysis, behavioral monitoring, and cross-server
flow tracking to detect and block known MCP attack classes.
"""

import json

from mcp_watchdog.smac import SMACPreprocessor
from mcp_watchdog.entropy import EntropyAnalyzer
from mcp_watchdog.behavioral import BehavioralMonitor
from mcp_watchdog.flow_tracker import FlowTracker
from mcp_watchdog.alerts import WatchdogAlert, print_alert


class MCPWatchdogProxy:
    def __init__(self, verbose: bool = True) -> None:
        self.smac = SMACPreprocessor()
        self.entropy = EntropyAnalyzer()
        self.behavioral = BehavioralMonitor()
        self.flow = FlowTracker()
        self.verbose = verbose

    async def process_response(
        self, raw: str, server_id: str
    ) -> tuple[str, list[WatchdogAlert]]:
        all_alerts: list[WatchdogAlert] = []

        # SMAC-L3 preprocessing on the raw message
        cleaned, smac_violations = self.smac.process(raw, server_id)
        for v in smac_violations:
            alert = WatchdogAlert(
                severity="high",
                server_id=server_id,
                rule=v.rule,
                detail=v.content_preview,
            )
            all_alerts.append(alert)
            if self.verbose:
                print_alert(alert)

        # Entropy analysis on cleaned content
        entropy_alerts = self.entropy.analyze(cleaned, server_id)
        for ea in entropy_alerts:
            alert = WatchdogAlert(
                severity=ea.severity,
                server_id=server_id,
                rule="ENTROPY",
                detail=ea.detail,
            )
            all_alerts.append(alert)
            if self.verbose:
                print_alert(alert)

        # Cross-server flow tracking — record tokens from this response
        self.flow.record_response(server_id, cleaned)

        # Scan tool listings for prompt injection in descriptions
        try:
            parsed = json.loads(cleaned)
            result = parsed.get("result", {})
            if isinstance(result, dict) and "tools" in result:
                for tool in result["tools"]:
                    desc = tool.get("description", "")
                    if desc:
                        _, desc_violations = self.smac.process(desc, server_id)
                        desc_entropy = self.entropy.analyze(
                            json.dumps({"description": desc}), server_id
                        )
                        for v in desc_violations:
                            alert = WatchdogAlert(
                                severity="critical",
                                server_id=server_id,
                                rule=v.rule,
                                detail=f"Tool description injection: {v.content_preview}",
                            )
                            all_alerts.append(alert)
                            if self.verbose:
                                print_alert(alert)
                        for ea in desc_entropy:
                            alert = WatchdogAlert(
                                severity=ea.severity,
                                server_id=server_id,
                                rule="ENTROPY",
                                detail=f"Tool description: {ea.detail}",
                            )
                            all_alerts.append(alert)
                            if self.verbose:
                                print_alert(alert)
        except (json.JSONDecodeError, AttributeError):
            pass

        return cleaned, all_alerts

    async def process_request(
        self, raw: str, server_id: str
    ) -> tuple[str, list[WatchdogAlert]]:
        all_alerts: list[WatchdogAlert] = []
        flow_alerts = self.flow.record_request(server_id, raw)
        for fa in flow_alerts:
            alert = WatchdogAlert(
                severity=fa.severity,
                server_id=server_id,
                rule="CROSS-SERVER",
                detail=f"Data from {fa.source_server} -> {fa.target_server}: {fa.token_preview}",
            )
            all_alerts.append(alert)
            if self.verbose:
                print_alert(alert)
        return raw, all_alerts
