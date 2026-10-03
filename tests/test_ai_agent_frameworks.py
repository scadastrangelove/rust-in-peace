"""Offline tests for the ai-agent framework tracker (no network).

Verifies the track-don't-pin design: the manifest lists sources + resolvers,
verdict logic treats a newer upstream as expected ('evolved', not drift), and
the provenance lock records what a run observed.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_PACK = Path(__file__).resolve().parents[1] / "profiles" / "ai-agent"
_MANIFEST = _PACK / "frameworks.json"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "ai_agent_refresh_frameworks", _PACK / "refresh_frameworks.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rf = _load_module()


def test_manifest_valid_shape():
    m = json.loads(_MANIFEST.read_text())
    assert m["schema_version"] == 2
    assert m["frameworks"]
    ids = [fw["id"] for fw in m["frameworks"]]
    assert len(ids) == len(set(ids)), "framework ids are unique"
    for fw in m["frameworks"]:
        assert {"id", "name", "resolver"} <= fw.keys()
        assert fw["resolver"] in rf._RESOLVERS, f"{fw['id']}: known resolver"


def test_manifest_carries_no_authoritative_pin():
    """Track-don't-pin: entries use 'reference_version' (informational), never a
    'pinned_version' gate."""
    m = json.loads(_MANIFEST.read_text())
    for fw in m["frameworks"]:
        assert "pinned_version" not in fw, f"{fw['id']}: must not hard-pin"


@pytest.mark.parametrize("reference,current,expected", [
    ("v0.5.1", "v0.5.1", "current"),
    ("v0.5.1", "0.5.1", "current"),      # v-prefix insensitive
    ("2026", "2027", "evolved"),          # newer upstream is expected, not drift
    (None, "4.20", "baseline"),           # first observation
    ("4.16", None, "unresolved"),         # upstream unreachable
])
def test_verdict(reference, current, expected):
    assert rf.verdict(reference, current) == expected


def test_resolve_all_offline(monkeypatch):
    """resolve_all must tolerate a resolver raising (network down) -> unresolved,
    not crash."""
    monkeypatch.setitem(rf._RESOLVERS, "github_release_or_tag", lambda fw: "v9.9")
    monkeypatch.setitem(rf._RESOLVERS, "owasp_year", lambda fw: fw["reference_version"])
    def _boom(fw):
        raise RuntimeError("network down")
    monkeypatch.setitem(rf._RESOLVERS, "cwe_homepage", _boom)
    manifest = json.loads(_MANIFEST.read_text())
    rows = {r["id"]: r for r in rf.resolve_all(manifest)}
    assert rows["asamm"]["current_version"] == "v9.9"
    assert rows["asamm"]["verdict"] == "evolved"           # v0.5.1 -> v9.9
    assert rows["owasp-llm-top10"]["verdict"] == "current" # reference echoed
    assert rows["cwe"]["current_version"] is None           # raised -> unresolved
    assert rows["cwe"]["verdict"] == "unresolved"
    assert "network down" in rows["cwe"]["error"]


def test_selftest_passes(capsys):
    assert rf._selftest(_MANIFEST) == 0
    assert "SELFTEST PASS" in capsys.readouterr().out
