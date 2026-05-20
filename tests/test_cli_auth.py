# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Auth-resolver coverage: API key, OAuth token, none."""
import pytest

from harness.cli import _resolve_auth_env, NO_AUTH_MSG


AUTH_VARS = (
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)


@pytest.fixture(autouse=True)
def _clear_auth(monkeypatch):
    for v in AUTH_VARS:
        monkeypatch.delenv(v, raising=False)


def test_api_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    assert _resolve_auth_env() == {"ANTHROPIC_API_KEY": "sk-ant-x"}


def test_oauth_token(monkeypatch):
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
    assert _resolve_auth_env() == {"CLAUDE_CODE_OAUTH_TOKEN": "tok"}


def test_precedence_api_key_over_oauth(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-x")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "tok")
    assert _resolve_auth_env() == {"ANTHROPIC_API_KEY": "sk-ant-x"}


def test_none():
    assert _resolve_auth_env() is None


def test_error_message_names_all_modes():
    assert "ANTHROPIC_API_KEY" in NO_AUTH_MSG
    assert "CLAUDE_CODE_OAUTH_TOKEN" in NO_AUTH_MSG
