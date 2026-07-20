# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Target configuration loader.

A target is a directory under targets/ containing:
  - Dockerfile   (builds ASAN-instrumented binary)
  - config.yaml  (metadata the pipeline needs)
  - any other build-context files the Dockerfile COPYs

Adding a new target = new dir, zero pipeline code changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


def _safe_git_ref(ref: str, target_dir: Path) -> str:
    """Validate a config.yaml git ref (``commit``) before it is interpolated
    into a ``git`` argv (F4, self-review). A ref beginning with ``-`` would be
    parsed by git as an *option* rather than a revision (leading-dash argument
    injection, e.g. via ``novelty.py``'s ``git log <commit>..HEAD``). Real
    commit hashes and tags never start with ``-``, and refs may not contain
    whitespace/control chars, so reject those. Kept intentionally permissive
    otherwise (hashes AND tag-like refs such as ``0.18.0-beta.1`` are valid)."""
    ref = ref.strip()
    if not ref or ref.startswith("-") or any(c.isspace() for c in ref) or "\x00" in ref:
        raise ValueError(
            f"{target_dir.name}: invalid config `commit` {ref!r} — a git ref must "
            f"be non-empty, contain no whitespace, and not start with '-' "
            f"(argument-injection guard)")
    return ref


@dataclass(frozen=True)
class TargetConfig:
    name: str
    dockerfile_dir: str   # build context dir (the target dir itself)
    image_tag: str
    github_url: str
    commit: str
    binary_path: str      # path inside the built container
    source_root: str      # path inside the built container
    focus_areas: list[str] = field(default_factory=list)
    known_bugs: list[str] = field(default_factory=list)
    attack_surface: str | None = None
    build_command: str | None = None  # rebuild in-container after applying a patch (T0)
    test_command: str | None = None   # regression suite for T2; None → T2 skipped
    build_timeout_s: int = 1800
    shm_size: str | None = None       # docker --shm-size
    memory_limit: str = "4g"          # docker --memory
    reattack_harness: str | None = None  # in-image script that runs every /poc/* and exits 1 on crash
    profile: str = "rust"             # pipeline profile: "rust" (default) | "cpp" | ...;
                                      # selects find prompt, crash detector, grade/judge prompts.
                                      # rust-first fork → rust is the default; cpp targets set it explicitly
    capabilities_path: str | None = None  # host path to capabilities.json (§9 machine form);
                                      # relative → resolved under the target dir. None → no
                                      # capability routing (additive; older targets omit it).

    @classmethod
    def load(cls, target_dir: str | Path) -> TargetConfig:
        target_dir = Path(target_dir).resolve()
        config_path = target_dir / "config.yaml"
        if not config_path.exists():
            raise FileNotFoundError(f"No config.yaml in {target_dir}")

        with open(config_path) as f:
            cfg = yaml.safe_load(f)

        # capabilities.json path: relative entries resolve under the target dir
        # (that's where the threat-model skill writes it, next to config.yaml).
        cap_path = cfg.get("capabilities_path")
        if cap_path:
            cp = Path(cap_path)
            cap_path = str(cp if cp.is_absolute() else target_dir / cp)
        elif (target_dir / "capabilities.json").exists():
            cap_path = str(target_dir / "capabilities.json")  # convention default

        return cls(
            name=target_dir.name,
            dockerfile_dir=str(target_dir),
            profile=cfg.get("profile", "rust"),
            image_tag=cfg["image_tag"],
            github_url=cfg["github_url"],
            commit=_safe_git_ref(str(cfg["commit"]), target_dir),
            binary_path=cfg["binary_path"],
            source_root=cfg["source_root"],
            focus_areas=cfg.get("focus_areas") or [],
            known_bugs=cfg.get("known_bugs") or [],
            attack_surface=cfg.get("attack_surface"),
            build_command=cfg.get("build_command"),
            test_command=cfg.get("test_command"),
            build_timeout_s=cfg.get("build_timeout_s", 1800),
            shm_size=cfg.get("shm_size"),
            memory_limit=cfg.get("memory_limit", "4g"),
            reattack_harness=cfg.get("reattack_harness"),
            capabilities_path=cap_path,
        )
