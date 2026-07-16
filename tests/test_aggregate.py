# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for union-of-N aggregation (harness/aggregate.py)."""
import json

import pytest

from harness.aggregate import aggregate, count_runs, _site_key


def _mkrun(root, i, site_fn, status, ctype="heap-buffer-overflow", op="READ", line=None):
    d = root / f"run_{i:03d}"
    d.mkdir(parents=True)
    ln = i if line is None else line
    out = (f"==ERROR: AddressSanitizer: {ctype}\n"
           f"    #0 0x1 in {site_fn} /src/x.c:{ln}\n"
           f"    #1 0x2 in main /src/m.c:9")
    d.joinpath("result.json").write_text(json.dumps({
        "target": "t", "status": status,
        "crash": {"crash_output": out, "crash_type": ctype,
                  "poc_bytes": "AAAA" if i % 2 else "AA",
                  "reason": {"crash_type": ctype, "operation": op}},
    }))


def _mknocrash(root, i):
    d = root / f"run_{i:03d}"
    d.mkdir(parents=True)
    d.joinpath("result.json").write_text(json.dumps(
        {"target": "t", "status": "no_crash_found", "crash": None}))


def test_site_key_strips_line():
    assert _site_key("parse::read /src/p.rs:120:18") == "parse::read /src/p.rs"
    assert _site_key("parse_a /src/x.c:4") == "parse_a /src/x.c"
    assert _site_key("<no-frame>") == "<no-frame>"


def test_union_votes_across_lines(tmp_path):
    # parse_a found by runs 0,1,4 at THREE different lines → one candidate, 3 votes
    _mkrun(tmp_path, 0, "parse_a", "crash_found")
    _mkrun(tmp_path, 1, "parse_a", "crash_found")
    _mkrun(tmp_path, 2, "parse_b", "crash_rejected")
    _mknocrash(tmp_path, 3)
    _mkrun(tmp_path, 4, "parse_a", "crash_rejected")

    assert count_runs(tmp_path) == 5
    u = aggregate(tmp_path, "union")
    assert u.n_runs == 5
    a = next(c for c in u.candidates if "parse_a" in c.site)
    b = next(c for c in u.candidates if "parse_b" in c.site)
    assert a.votes == 3 and a.passed_votes == 2 and a.is_confirmed
    assert a.site == "parse_a /src/x.c"                 # line stripped
    assert b.votes == 1 and not b.is_confirmed


def test_majority_filter(tmp_path):
    _mkrun(tmp_path, 0, "parse_a", "crash_found")
    _mkrun(tmp_path, 1, "parse_a", "crash_found")
    _mkrun(tmp_path, 2, "parse_b", "crash_rejected")
    _mknocrash(tmp_path, 3)
    _mkrun(tmp_path, 4, "parse_a", "crash_rejected")
    m = aggregate(tmp_path, "majority")               # N=5 → need k*2>5 → k>=3
    assert len(m.candidates) == 1 and "parse_a" in m.candidates[0].site


def test_single_run_layout(tmp_path):
    tmp_path.joinpath("result.json").write_text(json.dumps({
        "target": "t", "status": "crash_found",
        "crash": {"crash_output": "==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                                  "    #0 0x1 in solo /s.c:1",
                  "crash_type": "heap-buffer-overflow", "poc_bytes": "AA",
                  "reason": {"crash_type": "heap-buffer-overflow", "operation": "READ"}},
    }))
    assert count_runs(tmp_path) == 1
    u = aggregate(tmp_path, "union")
    assert u.n_runs == 1 and len(u.candidates) == 1


def test_bad_mode(tmp_path):
    with pytest.raises(ValueError):
        aggregate(tmp_path, "nope")


def test_to_dict_shape(tmp_path):
    _mkrun(tmp_path, 0, "parse_a", "crash_found")
    _mkrun(tmp_path, 1, "parse_a", "crash_found")
    d = aggregate(tmp_path, "union").to_dict()
    assert d["mode"] == "union" and d["n_candidates"] == 1
    assert d["candidates"][0]["vote_fraction"] == "2/2"
    assert d["candidates"][0]["confirmed"] is True
