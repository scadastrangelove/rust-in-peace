# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Rust crash-output parsing — drop-in analog of harness/asan.py.

Exposes the SAME public surface as asan.py (`project_frames`, `top_frame`,
`crash_reason`, plus `excerpt` aliased to `asan_excerpt`) so the generic
pipeline (cli.py bug-sharing jsonl, dedup.py) can switch detectors by import
swap — no orchestration change.

Handles the four Rust crash oracles this profile uses:
  1. panic         — `thread '..' panicked at file:line:col:\\n<message>`
                     classified by message (index-oob, slice-range, unwrap-none/
                     err, arith-overflow, capacity, other). Backtrace frames come
                     from RUST_BACKTRACE=1.
  2. miri-ub       — `error: Undefined Behavior: <kind>` with `--> file:line`
                     and `= note: inside `path` at file:line` backtrace frames.
                     The gold signal for unsafe/FFI bugs.
  3. asan-<type>   — `-Zsanitizer=address` output (same shape as C ASAN, but
                     symbol names are demangled Rust paths). Reuses ASAN regex.
  4. abort         — SIGABRT / process abort with no structured trace.

Dedup signature = (crash_type, top project frames), skipping panic/UB machinery
frames (rust_begin_unwind, core::panicking::*, /rustc/ std frames) so two inputs
that trip the same site collapse regardless of the exact panic plumbing.
"""
from __future__ import annotations

import re

# ---- Rust backtrace frames (RUST_BACKTRACE=1) -----------------------------
# "  12: crate::module::function"  then a following "             at ./src/f.rs:9:5"
_RS_FRAME = re.compile(r"^\s*(\d+):\s+(.+?)\s*$", re.MULTILINE)
_RS_AT = re.compile(r"^\s*at\s+(.+?):(\d+)(?::\d+)?\s*$")
# Miri backtrace frame: "= note: inside `foo::bar` at src/f.rs:12:5"
_MIRI_FRAME = re.compile(
    r"inside\s+`?(.+?)`?\s+at\s+([^\s:]+):(\d+)(?::\d+)?", re.MULTILINE
)
# ASAN frame (reused from asan.py): "  #3 0x... in <demangled> file:line"
_ASAN_FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s*$", re.MULTILINE)
_SOURCE_LOC = re.compile(r"\s[/\w][^\s:]*:\d+(?=(?::\d+)?$)")

# Frames that are panic/UB plumbing, not the bug site — never a signature frame.
_MACHINERY = re.compile(
    r"""(?x)
    ^(std|core|alloc)::
    | rust_begin_unwind
    | core::panicking
    | std::panicking
    | core::result::unwrap_failed
    | core::option::expect_failed
    | core::slice::index
    | \bpanic_(bounds_check|fmt|misaligned|null_pointer)\b
    | ___rust_
    | __rust_
    """
)
# std/toolchain source paths that aren't the project.
_TOOLCHAIN_PATH = re.compile(r"(^/rustc/|/library/(std|core|alloc)/|/\.cargo/registry/)")


def _is_project_frame(sym: str, path: str | None) -> bool:
    if _MACHINERY.search(sym):
        return False
    if path and _TOOLCHAIN_PATH.search(path):
        return False
    return True


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Top-N project frames (symbol [+ file:line]) — the dedup signature.

    Tries, in order: Rust panic backtrace, Miri UB backtrace, ASAN trace.
    Skips panic/UB machinery and toolchain frames. Falls back to the first
    non-machinery frame if none carry a project source path, so the caller
    always has *something*.
    """
    out: list[str] = []
    fallback: str | None = None

    # 1. Rust panic backtrace: "N: sym" optionally followed by "at file:line".
    lines = crash_output.splitlines()
    i = 0
    while i < len(lines):
        m = _RS_FRAME.match(lines[i])
        if m:
            sym = m.group(2)
            path = None
            if i + 1 < len(lines):
                at = _RS_AT.match(lines[i + 1])
                if at:
                    path = at.group(1)
            if not _MACHINERY.search(sym):
                if fallback is None:
                    fallback = sym
                if _is_project_frame(sym, path):
                    frame = sym if path is None else f"{sym} {path}:{_RS_AT.match(lines[i + 1]).group(2)}"
                    out.append(frame)
                    if len(out) >= n:
                        return out
        i += 1
    if out:
        return out

    # 2. Miri UB backtrace: "inside `path` at file:line".
    for sym, path, line in _MIRI_FRAME.findall(crash_output):
        if fallback is None:
            fallback = sym
        if _is_project_frame(sym, path):
            out.append(f"{sym} {path}:{line}")
            if len(out) >= n:
                return out
    if out:
        return out

    # 3. ASAN trace (same walk as asan.py).
    frames = _ASAN_FRAME.findall(crash_output)
    prev = -1
    for n_str, body in frames:
        fn = int(n_str)
        if fn <= prev:
            break
        prev = fn
        if _MACHINERY.search(body):
            continue
        if fallback is None:
            fallback = body
        loc = _SOURCE_LOC.search(body)
        if loc and not _TOOLCHAIN_PATH.search(body):
            out.append(body[: loc.end()])
            if len(out) >= n:
                break
    return out or ([fallback] if fallback else [])


def top_frame(crash_output: str) -> str | None:
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


# ---- crash_type classification --------------------------------------------
_PANIC = re.compile(r"panicked at\b")
_MIRI = re.compile(r"error:\s+Undefined Behavior:\s*(.+)")
_ASAN_SUMMARY = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(\S+)")
_OP = re.compile(
    r"^(READ|WRITE) of size \d+|signal is caused by a (READ|WRITE) memory access",
    re.MULTILINE,
)

# Panic message → a stable class (the "SUMMARY" analog for panics).
_PANIC_CLASSES = [
    (re.compile(r"index out of bounds"), "panic-index-oob"),
    (re.compile(r"slice index|range (start|end) index|out of range for slice"), "panic-slice-range"),
    (re.compile(r"byte index .* is (out of bounds|not a char boundary)"), "panic-str-boundary"),
    (re.compile(r"called `Option::unwrap\(\)` on a `None`|unwrap.*on.*None"), "panic-unwrap-none"),
    (re.compile(r"called `Result::unwrap\(\)` on an `Err`|unwrap.*on.*Err"), "panic-unwrap-err"),
    (re.compile(r"attempt to (add|subtract|multiply|negate|divide|shift).*overflow"), "panic-arith-overflow"),
    (re.compile(r"attempt to divide by zero|remainder with a divisor of zero"), "panic-div-zero"),
    (re.compile(r"capacity overflow"), "panic-capacity"),
    (re.compile(r"unaligned|misaligned pointer dereference"), "panic-misaligned"),
]


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """crash_type (+ operation for ASAN) parsed from Rust crash output.

    Display/dedup helper — agents judge semantic duplicates from the raw trace.
    Precedence: Miri UB (strongest signal) > ASAN > panic > abort.
    """
    m = _MIRI.search(crash_output)
    if m:
        kind = m.group(1).strip().split(":")[0].split(",")[0][:48]
        return {"crash_type": f"miri-ub:{kind}", "operation": None}

    m = _ASAN_SUMMARY.search(crash_output)
    if m:
        op = _OP.search(crash_output)
        operation = (op.group(1) or op.group(2)) if op else None
        return {"crash_type": f"asan-{m.group(1)}", "operation": operation}

    if _PANIC.search(crash_output):
        for pat, label in _PANIC_CLASSES:
            if pat.search(crash_output):
                return {"crash_type": label, "operation": None}
        return {"crash_type": "panic-other", "operation": None}

    if re.search(r"\bSIGABRT\b|Aborted|process abort", crash_output):
        return {"crash_type": "abort", "operation": None}

    return {"crash_type": None, "operation": None}


def excerpt(crash_output: str, max_frames: int = 10) -> str:
    """Header line(s) + first N frames, for dedup context (~500 bytes)."""
    lines = crash_output.splitlines()
    out: list[str] = []
    frames = 0
    for line in lines:
        s = line.strip()
        if (
            s.startswith("SUMMARY:")
            or "ERROR: AddressSanitizer:" in s
            or s.startswith("error: Undefined Behavior:")
            or "panicked at" in s
        ):
            out.append(s)
        elif re.match(r"^\d+:\s", s) or s.startswith("#") and " 0x" in s or s.startswith("= note: inside"):
            out.append(s)
            frames += 1
            if frames >= max_frames:
                break
    if not out:
        out = [l.strip() for l in lines if l.strip()][:3]
    return "\n".join(out)


# asan.py-compatible alias so imports can swap `asan_excerpt` → this module.
asan_excerpt = excerpt
