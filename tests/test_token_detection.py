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


def test_github_pat_various_lengths_redacted():
    """SMAC-6 must catch GitHub PATs of varying lengths, not just exactly 36 chars."""
    proc = SMACPreprocessor()
    # 34-char suffix PAT (shorter than current regex expects)
    short_pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    raw = f'{{"result": "token={short_pat}"}}'
    cleaned, violations = proc.process(raw, "test")
    assert short_pat not in cleaned, f"Short GitHub PAT survived: {cleaned}"
    assert any(v.rule == "SMAC-6" for v in violations)

    # 40-char suffix PAT (longer)
    long_pat = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
    raw2 = f'{{"result": "token={long_pat}"}}'
    cleaned2, violations2 = proc.process(raw2, "test")
    assert long_pat not in cleaned2, f"Long GitHub PAT survived: {cleaned2}"
    assert any(v.rule == "SMAC-6" for v in violations2)


def test_gho_token_various_lengths():
    """SMAC-6 must catch gho_ OAuth tokens of varying lengths."""
    proc = SMACPreprocessor()
    short_tok = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    raw = f'{{"result": "{short_tok}"}}'
    cleaned, violations = proc.process(raw, "test")
    assert short_tok not in cleaned, f"Short gho_ token survived: {cleaned}"
    assert any(v.rule == "SMAC-6" for v in violations)


def test_aws_secret_key_redacted():
    """SMAC-6 must catch AWS secret access keys (wJalrXUtnFEMI...)."""
    proc = SMACPreprocessor()
    dirty = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    clean, violations = proc.process(dirty, "srv")
    assert "wJalrXUtnFEMI" not in clean, f"AWS secret key survived: {clean}"
    assert any(v.rule == "SMAC-6" for v in violations)


def test_aws_secret_key_lowercase_redacted():
    """SMAC-6 must catch lowercase aws_secret_access_key labels too."""
    proc = SMACPreprocessor()
    dirty = 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    clean, violations = proc.process(dirty, "srv")
    assert "wJalrXUtnFEMI" not in clean, f"AWS secret key survived: {clean}"
    assert any(v.rule == "SMAC-6" for v in violations)


def test_slack_three_segment_token_redacted():
    """SMAC-6 must catch 3-segment Slack bot tokens (xoxb-NUM-NUM-ALPHA)."""
    proc = SMACPreprocessor()
    # Build token dynamically to avoid GitHub secret scanning
    prefix = "xoxb-"
    team_id = "123456789012"
    bot_id = "1234567890123"
    secret = "AbCdEfGhIjKlMnOpQrStUvWx"
    token = prefix + team_id + "-" + bot_id + "-" + secret
    dirty = '{"result": "' + token + '"}'
    clean, violations = proc.process(dirty, "srv")
    assert "xoxb-" not in clean, f"3-segment Slack token survived: {clean}"
    assert any(v.rule == "SMAC-6" for v in violations)


def test_normal_text_not_flagged():
    proc = SMACPreprocessor()
    clean_input = '{"result": "Project has 42 files, last commit 2h ago"}'
    clean, violations = proc.process(clean_input, "srv")
    assert not any(v.rule == "SMAC-6" for v in violations)
