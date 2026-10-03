#!/usr/bin/env python3
"""End-to-end replay reproducer for the ai-agent profile (needs Docker + a built image).

This is NOT a unit test (CI has no Docker); it drives the REAL verifier
`harness.ai_agent.runtime.replay` -> `evidence.assess` against a built target image,
spinning a fresh, network-isolated, read-only, non-root victim container per control
and per attack. It is the operator-side confirmation the grade/aggregate stages do
not call yet (see IMPLEMENTATION.md).

Build the canary first, then run from the repo root:

    docker build -t ai-agent-canary:e2e targets/ai-agent-canary
    python profiles/ai-agent/e2e_replay.py

Verified on the host (gordey@85.142.100.8) 2026-10-03: vault-read -> confirmed 3/3,
public-decoy -> not_observed 0/3, delayed-export -> confirmed 3/3.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from harness.ai_agent import contracts, evidence, runtime

_REPO = Path(__file__).resolve().parents[2]
_CANARY = _REPO / "targets" / "ai-agent-canary" / "target-contract.json"
_FIX = _REPO / "tests" / "fixtures" / "ai-agent-canary"
# (scenario file, expected disposition or None to just report)
_CASES = [
    ("vault-read.json", "confirmed"),        # real bug: vault.read without a token
    ("public-decoy.json", "not_observed"),   # false positive: public.info must not confirm
    ("delayed-export.json", None),           # deferred worker trigger (full_chain)
    ("unlisted-category.json", None),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--image", default="ai-agent-canary:e2e")
    ap.add_argument("--contract", default=str(_CANARY))
    ap.add_argument("--scenario", action="append", help="scenario JSON (repeatable); default = canary fixtures")
    args = ap.parse_args(argv)

    contract = contracts.load(args.contract, "target-contract")
    cases = [(s, None) for s in args.scenario] if args.scenario else \
            [(str(_FIX / name), exp) for name, exp in _CASES]

    rc = 0
    for path, expected in cases:
        try:
            scenario = contracts.load(path, "scenario")
            ev = runtime.replay(scenario, contract, args.image)
            a = evidence.assess(ev, scenario, contract)
        except Exception as e:  # infra/Docker/contract error — report, do not crash the batch
            print(f"{Path(path).name}: ERROR {type(e).__name__}: {e}")
            rc = 1
            continue
        verdict = "OK" if (expected is None or a.disposition == expected) else "MISMATCH"
        if expected is not None and a.disposition != expected:
            rc = 1
        exp = f" expected={expected}" if expected else ""
        print(f"{Path(path).name}: {a.disposition} ({a.successes}/{a.completed} of {a.scheduled}){exp}  [{verdict}]")
        print(f"    {a.reason}")
    print("E2E_RESULT:", "PASS" if rc == 0 else "FAIL")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
