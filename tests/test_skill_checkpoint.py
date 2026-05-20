# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for .claude/skills/_lib/checkpoint.py.

Payload always via --from <file>; stdin is rejected to prevent heredoc-
delimiter shell injection. All paths are confined to CHECKPOINT_ROOT (cwd in
production) so a prompt-injected agent can't append/reset outside the repo.
"""
import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / ".claude" / "skills" / "_lib" / "checkpoint.py"
_spec = importlib.util.spec_from_file_location("checkpoint", _SCRIPT)
assert _spec and _spec.loader
ckpt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ckpt)


@pytest.fixture(autouse=True)
def _root(tmp_path, monkeypatch):
    monkeypatch.setattr(ckpt, "_ROOT", tmp_path.resolve())


def _f(tmp_path, content):
    p = tmp_path / "_chunk.tmp"
    p.write_text(content)
    return str(p)


# ── happy path ───────────────────────────────────────────────────────────────

def test_save_then_load(tmp_path, capsys):
    state = tmp_path / ".test-state"
    src = _f(tmp_path, '{"findings": [1, 2]}')
    assert ckpt.main(["save", str(state), "2", "detect", "--from", src]) == 0
    assert json.loads((state / "phase2.json").read_text()) == {"findings": [1, 2]}
    prog = json.loads((state / "progress.json").read_text())
    assert prog == {"status": "running", "phase_done": 2, "shards_done": [],
                    "updated": prog["updated"]}
    capsys.readouterr()
    assert ckpt.main(["load", str(state)]) == 0
    assert json.loads(capsys.readouterr().out)["phase_done"] == 2


def test_save_stage_key(tmp_path):
    state = tmp_path / ".tm-state"
    src = _f(tmp_path, '{"x": 1}')
    assert ckpt.main(["save", str(state), "3", "--key", "stage", "--from", src]) == 0
    assert (state / "stage3.json").exists()
    assert json.loads((state / "progress.json").read_text())["stage_done"] == 3


def test_shard_then_save_clears_shards(tmp_path):
    state = tmp_path / ".s-state"
    src = _f(tmp_path, "{}")
    ckpt.main(["save", str(state), "1", "--from", src])
    for sid in ("a", "b"):
        ckpt.main(["shard", str(state), sid, "--from", _f(tmp_path, '{"r": 1}')])
    prog = json.loads((state / "progress.json").read_text())
    assert prog["shards_done"] == ["a", "b"] and prog["phase_done"] == 1
    assert (state / "shard_a.json").exists()
    ckpt.main(["save", str(state), "2", "--from", src])
    assert json.loads((state / "progress.json").read_text())["shards_done"] == []


def test_done(tmp_path):
    state = tmp_path / ".s-state"
    assert ckpt.main(["done", str(state), "5"]) == 0
    prog = json.loads((state / "progress.json").read_text())
    assert prog["status"] == "complete" and prog["phase_done"] == 5


def test_load_no_state(tmp_path, capsys):
    assert ckpt.main(["load", str(tmp_path / ".absent-state")]) == 0
    assert json.loads(capsys.readouterr().out) == {"status": "absent"}


def test_append(tmp_path):
    out = tmp_path / "FINDINGS.md"
    for chunk in ("# header", "## finding 1\nbody"):
        ckpt.main(["append", str(out), "--from", _f(tmp_path, chunk)])
    assert out.read_text() == "# header\n## finding 1\nbody\n"


def test_reset(tmp_path):
    state = tmp_path / ".s-state"
    (state / "x").mkdir(parents=True)
    assert ckpt.main(["reset", str(state)]) == 0
    assert not state.exists()
    assert ckpt.main(["reset", str(state)]) == 0  # idempotent


# ── input hardening ──────────────────────────────────────────────────────────

def test_save_rejects_bad_json(tmp_path):
    src = _f(tmp_path, "{not json")
    with pytest.raises(SystemExit) as e:
        ckpt.main(["save", str(tmp_path / ".s-state"), "1", "--from", src])
    assert e.value.code == 1
    assert not (tmp_path / ".s-state" / "phase1.json").exists()


def test_payload_requires_from(tmp_path):
    for cmd in (["save", str(tmp_path / ".s-state"), "1"],
                ["shard", str(tmp_path / ".s-state"), "x"],
                ["append", str(tmp_path / "out.md")]):
        with pytest.raises(SystemExit) as e:
            ckpt.main(cmd)
        assert e.value.code == 2


# ── path confinement ─────────────────────────────────────────────────────────

def test_confine_rejects_escape(tmp_path):
    # CHECKPOINT_ROOT is tmp_path; anything outside (or traversing out) is refused.
    outside = tmp_path.parent / "elsewhere"
    for cmd in (["append", str(outside / "x.md"), "--from", _f(tmp_path, "x")],
                ["reset", str(outside / ".x-state")],
                ["save", str(tmp_path / ".." / ".s-state"), "1",
                 "--from", _f(tmp_path, "{}")]):
        with pytest.raises(SystemExit) as e:
            ckpt.main(cmd)
        assert e.value.code == 2


def test_reset_requires_state_suffix(tmp_path):
    d = tmp_path / "not_a_state_dir"
    d.mkdir()
    with pytest.raises(SystemExit):
        ckpt.main(["reset", str(d)])
    assert d.exists()  # untouched


def test_safe_token_rejects_traversal(tmp_path):
    src = _f(tmp_path, "{}")
    state = tmp_path / ".s-state"
    with pytest.raises(SystemExit):
        ckpt.main(["save", str(state), "1", "--key", "../etc", "--from", src])
    with pytest.raises(SystemExit):
        ckpt.main(["shard", str(state), "../x", "--from", src])
