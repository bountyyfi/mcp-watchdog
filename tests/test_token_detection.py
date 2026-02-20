from mcp_watchdog.smac import SMACPreprocessor


def test_github_pat_redacted():
    proc = SMACPreprocessor()
    dirty = '{"result": "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"}'
    clean, violations = proc.process(dirty, "srv")
    assert "ghp_" not in clean
    assert any(v.rule == "SMAC-6" for v in violations)


def test_aws_key_redacted():
    proc = SMACPreprocessor()
    dirty = '{"result": "Key: AKIAIOSFODNN7EXAMPLE"}'
    clean, violations = proc.process(dirty, "srv")
    assert "AKIA" not in clean
    assert any(v.rule == "SMAC-6" for v in violations)


def test_openai_key_redacted():
    proc = SMACPreprocessor()
    dirty = '{"result": "sk-proj-abcdefghijklmnopqrstuvwxyz1234"}'
    clean, violations = proc.process(dirty, "srv")
    assert "sk-proj-" not in clean


def test_slack_token_redacted():
    proc = SMACPreprocessor()
    # Build token dynamically to avoid GitHub secret scanning
    prefix = "xoxb-"
    numbers = "1234567890"
    suffix = "abcdefghijklmnopqrst"
    token = prefix + numbers + "-" + suffix
    dirty = '{"result": "' + token + '"}'
    clean, violations = proc.process(dirty, "srv")
    assert "xoxb-" not in clean


def test_jwt_redacted():
    proc = SMACPreprocessor()
    dirty = '{"result": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}'
    clean, violations = proc.process(dirty, "srv")
    assert "eyJ" not in clean


def test_normal_text_not_flagged():
    proc = SMACPreprocessor()
    clean_input = '{"result": "Project has 42 files, last commit 2h ago"}'
    clean, violations = proc.process(clean_input, "srv")
    assert not any(v.rule == "SMAC-6" for v in violations)
