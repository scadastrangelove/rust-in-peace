# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/redact.py — F3 secret redaction (self-review)."""
from __future__ import annotations

from harness import redact


def test_scrub_replaces_live_token(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-SUPERSECRETVALUE123456789")
    redact.reset_cache()
    s = '{"out":"ANTHROPIC_API_KEY=sk-ant-SUPERSECRETVALUE123456789 done"}'
    out = redact.scrub(s)
    assert "SUPERSECRET" not in out
    assert redact.PLACEHOLDER in out


def test_scrub_multiple_secret_kinds(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "oauth-tok-abcdefghijklmnop")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "bedrock-tok-qrstuvwxyz012345")
    redact.reset_cache()
    out = redact.scrub("a oauth-tok-abcdefghijklmnop b bedrock-tok-qrstuvwxyz012345 c")
    assert "oauth-tok" not in out and "bedrock-tok" not in out


def test_scrub_noop_without_secrets(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "AWS_BEARER_TOKEN_BEDROCK",
              "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    redact.reset_cache()
    s = '{"out":"nothing secret here"}'
    assert redact.scrub(s) == s


def test_scrub_ignores_short_values(monkeypatch):
    # A trivially short env value must not be redacted (would nuke common substrings).
    monkeypatch.setenv("ANTHROPIC_API_KEY", "abc")
    redact.reset_cache()
    assert redact.scrub("abc def abc") == "abc def abc"
