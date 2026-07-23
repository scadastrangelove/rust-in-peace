# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the android-canary dynamic-promotion demo — each recorded observation
fixture drives the real promotion engine to its declared outcome (fixture ↔ engine
self-consistency), proving the strength-1 → strength-2/3 path without a device."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness import witness as W
from harness.android_app import promote as P

OBSDIR = Path(__file__).resolve().parents[1] / "targets" / "android-canary" / "observations"
FIXTURES = sorted(OBSDIR.glob("*.json"))


def _promote(d):
    static = W.SecurityWitness(
        kind=W.KIND_STATIC_REACHABILITY, strength=1,
        severity=d.get("severity", "MEDIUM"), finding_class=d["finding_class"])
    return P.promote_finding(
        static, P.Observation(**d["observation"]),
        capability=d.get("capability"), native_reachable=d.get("native_reachable", False))


def test_fixtures_exist():
    assert FIXTURES, "no observation fixtures found"


@pytest.mark.parametrize("path", FIXTURES, ids=lambda p: p.stem)
def test_fixture_promotes_as_declared(path):
    d = json.loads(path.read_text())
    exp = d["expected"]
    pr = _promote(d)
    assert pr.verdict == exp["verdict"], f"{path.stem}: {pr.detail}"
    assert pr.witness.strength == exp["strength"]
    if exp.get("tier") is not None:
        assert pr.witness.tier == exp["tier"]
    if exp.get("domain") is not None:
        assert pr.witness.domain == exp["domain"]


def test_tier_b_webview_reaches_strength3():
    d = json.loads((OBSDIR / "webview-js-bridge.json").read_text())
    pr = _promote(d)
    assert pr.promoted and pr.witness.strength == 3
    assert pr.witness.tier == "heavy_instrumented"


def test_decoy_guard_holds_under_dynamic_too():
    d = json.loads((OBSDIR / "decoy-guarded.json").read_text())
    pr = _promote(d)
    assert pr.verdict == P.V_GUARD_HELD and not pr.promoted
