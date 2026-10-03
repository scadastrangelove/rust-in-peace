# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Detector surface for the ai-agent profile (behavioral findings, not crashes).

The generic pipeline resolves a detector by sniffing the finder's
`<crash_output>` text (`profiles.detector_for_output`), never from a stack
trace. An ai-agent finding carries an `AIAGENT:` header instead of an ASan/
panic trace:

    AIAGENT: invariant=<id> component=<name> scope=<static_path|component|shipping_entrypoint|full_chain>
    attacker: <principal>
    entry: <entry point>
    guard: <guard that should have held>
    effect: <unauthorized effect on the protected asset>

Dedup identity is the invariant plus the component, NOT a source line. So
`crash_reason.crash_type` is the invariant id and `top_frame` is
`"<component> <entry>-><effect>"` with no `:line` suffix (which `aggregate._site_key`
would otherwise mangle). Everything is tolerant: a missing header degrades to a
single generic bucket rather than raising.
"""
from __future__ import annotations

import re

_HEADER = re.compile(r"^\s*AIAGENT:\s*(.*)$", re.MULTILINE)
_KV = re.compile(r"(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)")  # key=value, value may hold spaces
_ROLE = re.compile(r"^\s*(attacker|entry|guard|effect|via)\s*:\s*(.+?)\s*$", re.MULTILINE)


def _fields(crash_output: str) -> dict[str, str]:
    out: dict[str, str] = {}
    m = _HEADER.search(crash_output or "")
    if m:
        for k, v in _KV.findall(m.group(1)):
            out[k.lower()] = v.strip()
    for k, v in _ROLE.findall(crash_output or ""):
        out.setdefault(k.lower(), v.strip())
    return out


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Identity-bearing 'frames': component+entry->effect first, then role hops.

    Returns [] when there is no AIAGENT content to key on (tolerated downstream)."""
    f = _fields(crash_output)
    frames: list[str] = []
    component = f.get("component")
    entry = f.get("entry")
    effect = f.get("effect")
    if component or entry or effect:
        head = (component or "?").strip()
        if entry or effect:
            head = f"{head} {(entry or '?')}->{(effect or '?')}"
        frames.append(head)
    for role in ("guard", "via", "attacker"):
        if f.get(role):
            frames.append(f"{role}:{f[role]}")
    return frames[:n]


def top_frame(crash_output: str) -> str | None:
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """{'crash_type': <invariant id>, 'operation': None}. crash_type is the dedup key.

    The invariant id is always namespaced with an `aiagent:` prefix. The finder is
    instructed to emit it that way; we enforce it here so the prefix is a reliable
    marker. aggregate.Candidate.is_confirmed keys on it to route ai-agent findings
    to the trusted-replay confirmation path (passed_votes) and deny them the
    crash-model votes>=2 shortcut — a mislabeled invariant must never slip back
    into "two finders agreed = confirmed"."""
    f = _fields(crash_output)
    invariant = f.get("invariant")
    if not invariant:
        return {"crash_type": "aiagent:unclassified", "operation": None}
    if not invariant.startswith("aiagent:"):
        invariant = "aiagent:" + invariant
    return {"crash_type": invariant, "operation": None}


def excerpt(crash_output: str, max_frames: int = 10) -> str:
    """Compact, legible rendering: the AIAGENT header line + role lines, else head."""
    text = crash_output or ""
    kept: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("AIAGENT:") or _ROLE.match(line) or s.startswith("scope="):
            kept.append(s)
        if len(kept) >= max_frames:
            break
    if kept:
        return "\n".join(kept)
    return "\n".join([ln for ln in text.splitlines() if ln.strip()][:3])


# The pipeline calls `.asan_excerpt` on whatever detector it resolves.
asan_excerpt = excerpt
