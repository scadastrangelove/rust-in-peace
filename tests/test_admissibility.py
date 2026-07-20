# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/admissibility.py — P0.2 / P0.5 / P1.4 forcing functions."""
from __future__ import annotations

import pytest

from harness import admissibility as adm


def test_bare_claim_is_admissible():
    # A verdict relying on no special premise passes all gates.
    v = adm.check(adm.VerdictClaim(finding_id="f0"))
    assert v.state == adm.ADMISSIBLE
    assert adm.gate_grade(adm.VerdictClaim())


def test_dep_premise_without_citation_is_contested():
    # x509 L1: verdict rests on a dependency's accept-behaviour, uncited.
    v = adm.check(adm.VerdictClaim(
        rests_on_dependency_behavior=True, dep_citation=None))
    assert v.state == adm.CONTESTED
    assert not adm.gate_grade(adm.VerdictClaim(rests_on_dependency_behavior=True))


def test_dep_premise_with_bad_citation_is_contested():
    # A prose "asn1-rs rejects it" is not a file:line citation.
    v = adm.check(adm.VerdictClaim(
        rests_on_dependency_behavior=True, dep_citation="asn1-rs rejects it"))
    assert v.state == adm.CONTESTED


def test_dep_premise_with_file_line_citation_is_admissible():
    v = adm.check(adm.VerdictClaim(
        rests_on_dependency_behavior=True,
        dep_citation="vendor/asn1-rs/src/ber.rs:412"))
    assert v.state == adm.ADMISSIBLE


def test_reachable_claim_without_where_checked_is_contested():
    # P1.4/L3: a reachability assertion with no entry→sink trace.
    v = adm.check(adm.VerdictClaim(claims_reachable=True, where_checked=None))
    assert v.state == adm.CONTESTED
    v2 = adm.check(adm.VerdictClaim(claims_reachable=True, where_checked="   "))
    assert v2.state == adm.CONTESTED


def test_reachable_claim_with_trace_is_admissible():
    v = adm.check(adm.VerdictClaim(
        claims_reachable=True,
        where_checked="load_mem → parse_xref → parser_aux.rs:568"))
    assert v.state == adm.ADMISSIBLE


def test_construction_harness_is_unverified():
    # lopdf L12: reproduced by building the Document via the builder API.
    v = adm.check(adm.VerdictClaim(harness_kind=adm.HARNESS_DIRECT_CONSTRUCTION))
    assert v.state == adm.UNVERIFIED
    assert not adm.gate_grade(
        adm.VerdictClaim(harness_kind=adm.HARNESS_DIRECT_CONSTRUCTION))


def test_parse_entry_harness_is_admissible():
    v = adm.check(adm.VerdictClaim(harness_kind=adm.HARNESS_PARSE_ENTRY))
    assert v.state == adm.ADMISSIBLE


def test_unverified_beats_contested_when_both_trip():
    # Worst gate wins: a construction repro that also lacks a dep citation.
    v = adm.check(adm.VerdictClaim(
        rests_on_dependency_behavior=True, dep_citation=None,
        harness_kind=adm.HARNESS_DIRECT_CONSTRUCTION))
    assert v.state == adm.UNVERIFIED
    assert len(v.reasons) == 2   # both reasons surfaced


def test_bad_harness_kind_raises():
    with pytest.raises(ValueError):
        adm.VerdictClaim(harness_kind="magic")
