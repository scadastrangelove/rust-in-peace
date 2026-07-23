# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Android reachability-witness parsing — the android-app analog of asan.py.

Exposes the SAME public surface as asan.py / rust/detect.py
(`project_frames`, `top_frame`, `crash_reason`, plus `excerpt`/`asan_excerpt`)
so the generic pipeline (find bug-sharing jsonl, dedup, aggregate) switches
detectors by import swap — no orchestration change.

The "crash output" this detector parses is not a stack trace: it is a
**SecurityWitness** (see harness/witness.py) — a machine header line followed by
an entry → guard → sink reachability path over decompiled Android code:

    WITNESS: kind=static_reachability strength=1 severity=HIGH class=android:exported-activity-launch domain=- tier=-
    entry: com.app.ExportedActivity (exported=true, no permission)  AndroidManifest.xml
      --> smali/com/app/ExportedActivity.smali:42  onCreate reads getIntent().getData()
    guard: none
    sink:  startActivity(forwarded intent)  smali/com/app/ExportedActivity.smali:88

* ``crash_reason`` → ``crash_type`` = the finding CLASS from the witness header
  (e.g. ``android:exported-activity-launch``), so dedup/aggregate key findings
  by class exactly as they key crashes by ASan/Miri type.
* ``project_frames`` → the path anchors (**sink first**, then entry, then
  intermediate hops), each ``symbol path:line``, skipping Android/AndroidX/Kotlin
  *framework* refs the same way rust/detect skips toolchain frames. The dedup
  signature is (finding_class, sink site): distinct sinks are distinct findings;
  the same sink reached from several entries is one finding.

Native crashes routed here (an ``android-native`` escalation that produced an
ASan trace) carry no WITNESS header; ``crash_reason`` falls back to the ASan
summary via the shared regexes so a promoted native finding still dedups.
"""
from __future__ import annotations

import re

from .. import witness as _witness

# ── path refs into the decompiled tree ───────────────────────────────────────
# smali / decompiled-java / manifest / resource file, optionally with :line[:col].
_SRC = re.compile(
    r"((?:[\w./$-]+/)?[\w.$-]+\.(?:smali|java|kt|xml))(?::(\d+))?"
)
# Role lines of a reachability path. `-->` / `via` are intermediate hops.
_ROLE = re.compile(r"^\s*(entry|guard|sink|via|-->)(?=[\s:])\s*:?\s*(.*)$", re.IGNORECASE)

# Framework code — not the app under analysis. Skipped as a signature anchor the
# way rust/detect skips /rustc/ and the registry (a bug in the app's own smali is
# the finding, not the framework it calls).
_FRAMEWORK_PATH = re.compile(
    r"(^|/)(android|androidx|kotlin|kotlinx|java|javax|com/google/android"
    r"|dalvik|libcore)/",
)

# Reuse the ASan summary regex for native findings promoted into this profile.
_ASAN_SUMMARY = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(\S+)")
_PANIC = re.compile(r"panicked at\b")

# A short human symbol for a role line: the first parenthesized-free token, or a
# method-ish name, before the path ref.
_SYMBOL = re.compile(r"^([\w.$<>]+)")


def _is_framework(path: str | None) -> bool:
    return bool(path and _FRAMEWORK_PATH.search(path))


def _frame_from_role(role: str, rest: str) -> tuple[str, str | None, str] | None:
    """(symbol, 'path:line' or None, role) for one role line, or None if it has
    no usable source ref / symbol."""
    m = _SRC.search(rest)
    path = None
    if m:
        path = m.group(1) if not m.group(2) else f"{m.group(1)}:{m.group(2)}"
        head = rest[: m.start()].strip()
    else:
        head = rest.strip()
    sym_m = _SYMBOL.match(head)
    sym = sym_m.group(1) if sym_m else (head.split()[0] if head.split() else role)
    if not sym and not path:
        return None
    return (sym or role, path, role.lower())


def _walk(crash_output: str) -> list[tuple[str, str | None, str]]:
    """All role frames in document order: (symbol, path|None, role)."""
    out: list[tuple[str, str | None, str]] = []
    for line in (crash_output or "").splitlines():
        rm = _ROLE.match(line)
        if not rm:
            continue
        role = "via" if rm.group(1) == "-->" else rm.group(1).lower()
        fr = _frame_from_role(role, rm.group(2))
        if fr:
            out.append(fr)
    return out


def _fmt(sym: str, path: str | None) -> str:
    return sym if not path else f"{sym} {path}"


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Top-N path anchors — the dedup signature. **Sink first** (the security
    effect is the most finding-identifying anchor), then entry, then hops.
    Framework refs are dropped; if that leaves nothing, the first role frame is
    the fallback so the caller always has something."""
    frames = _walk(crash_output)
    if not frames:
        return []

    def keep(fr: tuple[str, str | None, str]) -> bool:
        # Only frames with a real source ref anchor a signature — this drops
        # filler role lines ("guard: none") and keeps the walk on cited code.
        return fr[1] is not None and not _is_framework(fr[1])

    order = {"sink": 0, "entry": 1, "guard": 2, "via": 3}
    ranked = sorted(
        (fr for fr in frames if keep(fr)),
        key=lambda fr: order.get(fr[2], 4),
    )
    out = [_fmt(sym, path) for sym, path, _role in ranked][:n]
    if out:
        return out
    # everything was framework — fall back to the first role frame verbatim
    sym, path, _r = frames[0]
    return [_fmt(sym, path)]


def top_frame(crash_output: str) -> str | None:
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """finding class (as ``crash_type``) parsed from the witness header.

    Precedence: a WITNESS header (the app-security case) wins; otherwise fall
    back to an ASan summary / panic (a promoted android-native finding) so those
    still dedup; else ``android:unclassified``.
    """
    w = _witness.parse(crash_output)
    if w.kind != _witness.KIND_NATIVE_CRASH or w.finding_class:
        cls = w.finding_class or f"android:{w.kind}"
        return {"crash_type": cls, "operation": None}

    m = _ASAN_SUMMARY.search(crash_output or "")
    if m:
        return {"crash_type": f"asan-{m.group(1)}", "operation": None}
    if _PANIC.search(crash_output or ""):
        return {"crash_type": "native-panic", "operation": None}
    return {"crash_type": "android:unclassified", "operation": None}


def excerpt(crash_output: str, max_frames: int = 10) -> str:
    """WITNESS header + the entry/guard/sink path lines, for dedup context."""
    lines = (crash_output or "").splitlines()
    out: list[str] = []
    for line in lines:
        s = line.strip()
        if s.startswith("WITNESS:") or _ROLE.match(line) or "AddressSanitizer:" in s:
            out.append(s)
            if len(out) >= max_frames + 1:  # +1 for the header
                break
    if not out:
        out = [l.strip() for l in lines if l.strip()][:3]
    return "\n".join(out)


# asan.py-compatible alias so imports can swap `asan_excerpt` → this module.
asan_excerpt = excerpt
