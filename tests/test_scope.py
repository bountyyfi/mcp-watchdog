import pytest
from pathlib import Path
from mcp_watchdog.scope import FilesystemScopeEnforcer, ScopeViolation


def test_write_outside_scope_detected(tmp_path):
    enforcer = FilesystemScopeEnforcer(
        server_id="project-context",
        allowed_paths=[str(tmp_path / "project")],
    )
    violation = enforcer.check_write(str(Path.home() / ".git" / "config"))
    assert violation is not None
    assert violation.reason == "out_of_scope_write"


def test_write_to_git_config_flagged(tmp_path):
    enforcer = FilesystemScopeEnforcer(
        server_id="project-context",
        allowed_paths=[str(tmp_path)],
    )
    violation = enforcer.check_write(str(tmp_path / ".git" / "config"))
    assert violation is not None
    assert violation.severity == "critical"


def test_write_to_ssh_flagged():
    enforcer = FilesystemScopeEnforcer(server_id="test", allowed_paths=[])
    violation = enforcer.check_write(
        str(Path.home() / ".ssh" / "authorized_keys")
    )
    assert violation is not None
    assert violation.severity == "critical"


def test_write_within_scope_allowed(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    enforcer = FilesystemScopeEnforcer(
        server_id="project-context",
        allowed_paths=[str(project)],
    )
    violation = enforcer.check_write(str(project / "context.db"))
    assert violation is None


def test_mcp_config_write_flagged():
    enforcer = FilesystemScopeEnforcer(server_id="test", allowed_paths=[])
    mcp_config = str(
        Path.home() / ".claude" / "claude_desktop_config.json"
    )
    violation = enforcer.check_write(mcp_config)
    assert violation is not None
    assert violation.severity == "critical"
