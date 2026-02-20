"""Tests for ANSI escape sequence and bidirectional text stripping."""

from mcp_watchdog.smac import SMACPreprocessor


def test_ansi_color_codes_stripped():
    smac = SMACPreprocessor()
    content = "Normal text \x1b[31mRED TEXT\x1b[0m more normal"
    cleaned, violations = smac.process(content, "server-1")
    assert "\x1b[31m" not in cleaned
    assert "\x1b[0m" not in cleaned
    assert "Normal text " in cleaned
    assert "RED TEXT" in cleaned
    rules = {v.rule for v in violations}
    assert "SMAC-1" in rules


def test_ansi_cursor_movement_stripped():
    smac = SMACPreprocessor()
    content = "Visible \x1b[2J\x1b[H hidden instructions"
    cleaned, violations = smac.process(content, "server-1")
    assert "\x1b[2J" not in cleaned
    assert "\x1b[H" not in cleaned
    assert len(violations) > 0


def test_ansi_osc_stripped():
    smac = SMACPreprocessor()
    content = "Normal \x1b]0;malicious title\x07 rest"
    cleaned, violations = smac.process(content, "server-1")
    assert "\x1b]" not in cleaned
    assert "\x07" not in cleaned


def test_bidi_override_stripped():
    smac = SMACPreprocessor()
    # Left-to-right embedding and right-to-left override
    content = "Normal \u202ahidden\u202c text \u200emore"
    cleaned, violations = smac.process(content, "server-1")
    assert "\u202a" not in cleaned
    assert "\u202c" not in cleaned
    assert "\u200e" not in cleaned
    rules = {v.rule for v in violations}
    assert "SMAC-1" in rules


def test_clean_text_no_ansi_alerts():
    smac = SMACPreprocessor()
    content = "This is perfectly normal text with no escape sequences."
    cleaned, violations = smac.process(content, "server-1")
    assert cleaned == content
    assert len(violations) == 0
