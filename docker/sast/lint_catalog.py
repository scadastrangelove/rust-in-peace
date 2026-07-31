#!/usr/bin/env python3
"""Catalogue every clippy lint with its DEFAULT LEVEL — the attribution key for pruning.

Why this exists: the `sast-driven` mode runs clippy with every group enabled, because v1's premise is
"all defaults out of the box, prune from measured yield". Pruning is only data-driven if each hit can
be attributed to a family — otherwise the operator ranks ~825 individual lints by hand.

**What we can and cannot get, measured 2026-07-28.** `clippy-driver -W help` lists all 825 lints with
their *default level* (allow / warn / deny) — but it does NOT publish group membership
(pedantic/nursery/restriction/style/…). The authoritative group table lives in clippy's own
`lints.json`, which needs network we do not have at run time. So this file records what is actually
knowable and labels it honestly:

    default_allow  — opt-in. This is (almost exactly) pedantic ∪ nursery ∪ restriction ∪ cargo:
                     the lints we turned on deliberately, and therefore the noise under scrutiny.
    default_warn   — on by default: style / complexity / perf / suspicious.
    default_deny   — correctness. Clippy's own high-confidence set.

That three-way split answers the actual pruning question — *is the opt-in tier earning its noise?* —
without pretending to a taxonomy we cannot verify offline. Do not relabel these as "groups".

Two parsing traps this file exists to get right:
  * lint names print with **hyphens** (`clippy::absolute-paths`) but appear in cargo's JSON with
    **underscores** (`clippy::absolute_paths`). We normalize to underscores so the join works;
    getting this wrong silently yields a 0% attribution rate, which is exactly how v1 shipped a
    `clippy_lints_catalogued=0` manifest.
  * the table is right-aligned with deep, variable indentation — anchor on `clippy::`, not on columns.

Never raises: a parse failure writes `{}` and the caller reports the tier as un-attributed rather
than pretending the tagging worked.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys

# Deep, variable right-alignment; hyphenated names; then the default level and the description.
LINT_ROW = re.compile(r"\s(clippy::[a-z0-9_-]+)\s+(allow|warn|deny|forbid)\s{2,}(.*)$")


def main(out_path: str) -> int:
    try:
        proc = subprocess.run(
            ["clippy-driver", "-W", "help"], capture_output=True, text=True, timeout=180,
        )
    except Exception as exc:                                    # noqa: BLE001 — never fail the build
        print(f"lint_catalog: clippy-driver failed: {exc}", file=sys.stderr)
        json.dump({}, open(out_path, "w"))
        return 0

    lints: dict[str, dict[str, str]] = {}
    for line in ((proc.stdout or "") + "\n" + (proc.stderr or "")).splitlines():
        # search(), not match(): the table is right-aligned with deep, variable indentation, so the
        # pattern never sits at position 0.
        m = LINT_ROW.search(line)
        if not m:
            continue
        name, level, desc = m.group(1), m.group(2), m.group(3).strip()
        if "," in name:                                          # a group row, not a lint row
            continue
        lints[name.replace("-", "_")] = {                        # normalize to the JSON spelling
            "default": level,
            "tier": f"default_{level}",
            "desc": desc[:200],
        }

    json.dump(lints, open(out_path, "w"), indent=1, sort_keys=True)
    tiers: dict[str, int] = {}
    for v in lints.values():
        tiers[v["tier"]] = tiers.get(v["tier"], 0) + 1
    print(f"lint_catalog: {len(lints)} lints {tiers} -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "/opt/sast/clippy-lints.json"))
