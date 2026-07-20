# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Soak enumeration (P0.3) — distinct SITES, not the ignore-crashes counter.

Generalized from the lopdf campaign (LESSONS.md, operational notes). A fork-mode
soak run with `-ignore_crashes=1` keeps a *hit counter* — content_decode reported
`crash: 6911`. That number is NOT an enumeration: it is repeat-hits of a small
set of shallow bugs (all 6911 inputs deduped to a **single** panic site,
`parser/mod.rs:670`). The real enumeration is the saved crash *artifacts*
reproduced through the binary and deduped by panic `file:line`. We almost shipped
"6911 crashes" as if it were a finding count.

The dedup key is the same one the rest of the pipeline uses — `(crash_class,
top_frame)` via the profile detector (`dedup._signature`) — so this is
profile-agnostic for free: the detector is the swappable noun, and
`detector_for_output` sniffs cpp/rust/android witness output the same way `dedup`
does. Feed it the reproduced crash_output of each artifact; get back
`{(class, site): count}`.

The shell side (`scripts/run_fuzz_soak.sh`) reproduces each artifact through the
target binary to obtain those outputs; this module is the pure, testable core
that turns them into a site enumeration and a verdict-shaped report (P0.6: the
report leads with "N distinct sites", not a raw counter).
"""
from __future__ import annotations

from collections import Counter
from types import ModuleType
from typing import Iterable

from .dedup import NO_FRAME
from .profiles import detector_for_output


def site_of(crash_output: str, detector: ModuleType | None = None) -> tuple[str, str]:
    """The `(crash_class, top_frame)` signature of one reproduced crash. Detector
    is sniffed from the output if not given (so a mixed-profile soak dir still
    buckets correctly), mirroring `dedup._signature`."""
    out = crash_output or ""
    det = detector or detector_for_output(out)
    reason = det.crash_reason(out)
    crash_type = reason.get("crash_type") or "unknown"
    frame = det.top_frame(out) or NO_FRAME
    return (crash_type, frame)


def enumerate_sites(
    crash_outputs: Iterable[str],
    detector: ModuleType | None = None,
) -> dict[tuple[str, str], int]:
    """Distinct crash sites → how many artifacts reproduced there. The len of the
    result is the number the soak should report; the sum of the values is the raw
    counter (which is NOT the finding count)."""
    counts: Counter[tuple[str, str]] = Counter()
    for out in crash_outputs:
        counts[site_of(out, detector)] += 1
    return dict(counts)


def format_site_report(
    sites: dict[tuple[str, str], int],
    total_inputs: int | None = None,
) -> str:
    """Verdict-shaped soak summary (P0.6): lead with the number of DISTINCT
    sites, then per-site artifact counts — never a bare `crash: <counter>`."""
    n_sites = len(sites)
    total = total_inputs if total_inputs is not None else sum(sites.values())
    if n_sites == 0:
        return f"0 distinct crash sites ({total} crash input(s) reproduced) — clean.\n"
    ordered = sorted(sites.items(), key=lambda kv: (-kv[1], kv[0]))
    lines = [
        f"{n_sites} distinct crash site(s) across {total} crash input(s) "
        f"(the {total} is a repeat-hit counter, NOT a finding count):",
        "",
    ]
    for (crash_type, frame), count in ordered:
        where = f" in {frame}" if frame != NO_FRAME else ""
        lines.append(f"  [{count:>6}x]  {crash_type}{where}")
    lines.append("")
    return "\n".join(lines)


def done_line(target: str, sites: dict[tuple[str, str], int], total_inputs: int) -> str:
    """The machine-readable completion marker `scripts/run_fuzz_soak.sh` appends,
    carrying the enumeration so a poller reads sites, not a counter:

        SOAK-DONE-<target> distinct_sites=N crash_inputs=M
    """
    return (f"SOAK-DONE-{target} distinct_sites={len(sites)} "
            f"crash_inputs={total_inputs}")
