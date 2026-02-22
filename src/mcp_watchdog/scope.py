"""Filesystem scope enforcement for Thanatos Layer 4 persistence detection.

Monitors and blocks MCP server filesystem writes outside declared scope.
Flags writes to .git/config, .ssh/, .aws/, MCP config files, and other
sensitive locations that could be used for cross-session persistence.
"""

from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone

import os
import sys

# Blocked path fragments — use os.sep so matching works on both Unix and Windows.
# Each entry is normalized to the platform's separator at import time.
ALWAYS_BLOCK = [
    os.path.join(".git", "config"),
    os.path.join(".git", "hooks"),
    ".ssh",
    os.path.join(".aws", "credentials"),
    ".npmrc",
    os.path.join(".claude", "claude_desktop_config.json"),
    os.path.join(".cursor", "mcp.json"),
    os.path.join(".windsurf", "mcp.json"),
    os.path.join(".continue", "config.json"),
    os.path.join("Library", "Application Support", "Claude"),
    os.path.join("AppData", "Roaming", "Claude"),
]


@dataclass
class ScopeViolation:
    reason: str
    server_id: str
    path: str
    severity: str = "high"
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class FilesystemScopeEnforcer:
    def __init__(self, server_id: str, allowed_paths: list[str]) -> None:
        self.server_id = server_id
        self.allowed_paths = [Path(p).resolve() for p in allowed_paths]

    def check_write(self, path: str) -> ScopeViolation | None:
        target = Path(path)

        # Detect symlink escape attacks
        if target.is_symlink():
            real_target = target.resolve()
            # Compare the symlink's own parent+name against resolved real path
            if str(target.absolute()) != str(real_target):
                return ScopeViolation(
                    reason="symlink_escape",
                    server_id=self.server_id,
                    path=path,
                    severity="critical",
                )

        resolved = target.resolve()
        path_str = str(resolved)

        # Check against always-blocked paths (normalize separators for cross-platform)
        # On Windows, resolved paths use backslashes; on Unix, forward slashes.
        # ALWAYS_BLOCK entries are already os.sep-normalized at import time.
        norm_path = path_str.replace("/", os.sep).replace("\\", os.sep)
        if sys.platform == "win32":
            norm_path = norm_path.lower()
        for blocked in ALWAYS_BLOCK:
            check_blocked = blocked.lower() if sys.platform == "win32" else blocked
            if check_blocked in norm_path:
                return ScopeViolation(
                    reason="out_of_scope_write",
                    server_id=self.server_id,
                    path=path,
                    severity="critical",
                )

        # Check if within any allowed path
        for allowed in self.allowed_paths:
            try:
                resolved.relative_to(allowed)
                return None
            except ValueError:
                continue

        # Not in any allowed path
        return ScopeViolation(
            reason="out_of_scope_write",
            server_id=self.server_id,
            path=path,
            severity="high",
        )


def get_process_watcher(server_id: str, allowed_paths: list[str]):
    """Create a filesystem watcher using inotify (Linux) / FSEvents (macOS).

    Requires: pip install watchdog
    Returns (observer, handler) tuple, or (None, None) if watchdog is unavailable.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler

        enforcer = FilesystemScopeEnforcer(server_id, allowed_paths)

        class MCPWatchHandler(FileSystemEventHandler):
            def _check(self, path: str) -> None:
                v = enforcer.check_write(path)
                if v:
                    from mcp_watchdog.alerts import WatchdogAlert, print_alert

                    print_alert(
                        WatchdogAlert(
                            severity=v.severity,
                            server_id=server_id,
                            rule="SCOPE-L4",
                            detail=f"Out-of-scope write: {path}",
                        )
                    )

            def on_modified(self, event) -> None:
                if not event.is_directory:
                    self._check(event.src_path)

            def on_created(self, event) -> None:
                if not event.is_directory:
                    self._check(event.src_path)

        return Observer(), MCPWatchHandler()
    except ImportError:
        return None, None
