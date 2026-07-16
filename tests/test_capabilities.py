# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the §9 capabilities routing table (harness/capabilities.py)."""
import json

import pytest

from harness import capabilities as cap


def _inv():
    return cap.from_dict({
        "capabilities": {
            "untrusted_deserialization": {"present": "yes", "evidence": "serde"},
            "unsafe_trait_trust": "yes",                       # shorthand string
            "inbound_c_abi": {"present": "no", "evidence": "grep empty"},
            "outbound_ffi": {"present": "test_only", "evidence": "oracle only"},
            "brand_new_cap": {"present": "yes", "evidence": "forward-compat"},
        },
        "reachable_from_public_api": {"present": "no", "evidence": "lifted out of crate"},
    })


def test_present_and_active():
    inv = _inv()
    assert inv.is_active("untrusted_deserialization")
    assert inv.is_active("unsafe_trait_trust")          # shorthand parsed
    assert not inv.is_active("inbound_c_abi")           # no
    assert inv.is_active("outbound_ffi")                # test_only == active
    assert inv.is_active("brand_new_cap")               # unknown-but-present == active
    assert inv.present("multi_tenant_authz") == "no"    # absent == no


def test_gates_and_sanitizer_matrix():
    inv = _inv()
    gate_caps = {g.capability for g in inv.active_gates()}
    # active but unmapped key is omitted from gates (nothing to enable yet)
    assert "brand_new_cap" not in gate_caps
    assert "unsafe_trait_trust" in gate_caps
    assert "miri" in inv.sanitizers() and "asan" in inv.sanitizers()
    g = cap.gates_for("unsafe_trait_trust")
    assert g.sanitizer == "miri" and g.fuzz_rung == "adversarial_trait_impl"
    assert cap.gates_for("reachable_from_public_api") is None   # axis, not a gate


def test_skips_paper_trail():
    inv = _inv()
    assert ("inbound_c_abi", "grep empty") in inv.skips()


def test_reachability_axis():
    assert _inv().reachable_from_public_api() == "no"
    # absent axis defaults to unknown (only down-rank on an explicit 'no')
    bare = cap.from_dict({"capabilities": {"unsafe_simd": "yes"}})
    assert bare.reachable_from_public_api() == "unknown"


def test_bad_present_rejected():
    with pytest.raises(cap.CapabilityError):
        cap.from_dict({"capabilities": {"x": {"present": "maybe"}}})


def test_flat_layout_tolerated():
    inv = cap.from_dict({
        "unsafe_simd": {"present": "yes", "evidence": "core::arch"},
        "reachable_from_public_api": {"present": "yes", "evidence": "public parse()"},
    })
    assert inv.is_active("unsafe_simd")
    assert inv.reachable_from_public_api() == "yes"


def test_roundtrip():
    inv = _inv()
    inv2 = cap.from_dict(inv.to_dict())
    assert inv2.active_capabilities() == inv.active_capabilities()
    assert inv2.reachable_from_public_api() == "no"


def test_load_and_load_optional(tmp_path):
    p = tmp_path / "capabilities.json"
    p.write_text(json.dumps({"capabilities": {"unsafe_simd": {"present": "yes", "evidence": "x"}}}))
    assert cap.load(p).is_active("unsafe_simd")
    assert cap.load_optional(None) is None
    assert cap.load_optional(tmp_path / "missing.json") is None
    with pytest.raises(cap.CapabilityError):
        cap.load(tmp_path / "missing.json")
