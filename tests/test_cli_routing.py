# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Rust capability routing at the CLI boundary (P0.4 / L4)."""

from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from harness.cli import _cmd_run, _rust_crash_track_route
from harness.config import TargetConfig


def _target(tmp_path: Path, *, profile: str, capability: str) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "config.yaml").write_text(
        "\n".join(
            [
                f"profile: {profile}",
                "image_tag: test:latest",
                "github_url: https://example.invalid/repo",
                "commit: deadbeef",
                "binary_path: /work/entry",
                "source_root: /work/src",
            ]
        )
        + "\n"
    )
    (target / "capabilities.json").write_text(
        json.dumps(
            {
                "capabilities": {
                    capability: {"present": "yes", "evidence": "test fixture"}
                }
            }
        )
    )
    return target


def test_logic_only_rust_route_skips():
    target = TargetConfig(
        name="logic",
        dockerfile_dir=".",
        image_tag="logic:latest",
        github_url="https://example.invalid/repo",
        commit="deadbeef",
        binary_path="/work/entry",
        source_root="/work/src",
        profile="rust",
        capabilities_path=None,
    )
    inventory, reason = _rust_crash_track_route(target)
    assert inventory is None
    assert reason is None  # no inventory preserves compatibility


def test_cmd_run_records_logic_only_rust_skip_before_auth(tmp_path):
    target = _target(tmp_path, profile="rust", capability="multi_tenant_authz")
    results = tmp_path / "results"
    args = Namespace(
        target=str(target),
        results_dir=str(results),
        resume=None,
    )

    with patch(
        "harness.cli._resolve_auth_env",
        side_effect=AssertionError("auth must not be resolved for a routed skip"),
    ):
        assert _cmd_run(args) == 0

    records = list(results.glob("target/*/routing.json"))
    assert len(records) == 1
    record = json.loads(records[0].read_text())
    assert record["decision"] == "skip"
    assert record["next_stage"] == "curated_static"
    assert record["active_capabilities"] == ["multi_tenant_authz"]
    assert "blind" in record["reason"]


def test_android_witness_run_is_not_misrouted_as_a_byte_track(tmp_path):
    target_dir = _target(tmp_path, profile="android-app", capability="exported_ipc")
    target = TargetConfig.load(target_dir)
    inventory, reason = _rust_crash_track_route(target)
    assert inventory is not None
    assert reason is None
