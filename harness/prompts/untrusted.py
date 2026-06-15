# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Helpers for embedding attacker-influenced text in agent prompts.

Untrusted blocks are delimited with a per-prompt random nonce on both the
opening and closing tag. The embedded text (target stderr, ASAN output, text
another agent derived from it) is authored before the nonce exists, so it
cannot contain a matching closing tag; sanitization additionally neutralizes
any closing-tag lookalike so the block cannot even appear to terminate early.
"""

from __future__ import annotations

import re
import secrets

_CLOSING_TAG = re.compile(r"</\s*untrusted_data", re.IGNORECASE)


def make_nonce() -> str:
    """Per-prompt random delimiter id for <untrusted_data> blocks."""
    return secrets.token_hex(16)


def sanitize_untrusted(text: str) -> str:
    """Neutralize anything that could close an <untrusted_data> block early."""
    return _CLOSING_TAG.sub("<untrusted_data", text)


def untrusted_block(text: str, nonce: str) -> str:
    """Wrap attacker-influenced text in nonce-delimited isolation tags."""
    return (
        f'<untrusted_data id="{nonce}">\n'
        f"{sanitize_untrusted(text)}\n"
        f'</untrusted_data id="{nonce}">'
    )
