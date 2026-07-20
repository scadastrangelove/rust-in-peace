# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Corpus-as-regression (P2) — a crash found once must never return.

Every reproducing crash input is persisted into a per-target regression corpus
with a manifest, so a per-PR replay (`cargo test`-speed: feed each saved input to
the fuzz target, assert it still crashes on the OLD code and is fixed on the new)
catches a reintroduced bug immediately. This is the "corpus is a regression suite"
cross-cutting rule from `profiles/rust/fuzzing.md`, made concrete.

Pure/deterministic (no docker) so it is unit-testable: it lays out files + the
manifest; the actual replay runs on the build host from the target Dockerfile.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class RegressionEntry:
    finding_id: str
    cwe: str
    sanitizer: str          # the oracle that caught it — replay must use the same
    input_file: str         # path relative to the corpus root
    sha256: str
    reproduction_command: str
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def save_regression(
    corpus_root: str | Path,
    *,
    finding_id: str,
    cwe: str,
    sanitizer: str,
    crash_input: bytes,
    reproduction_command: str,
    note: str = "",
) -> RegressionEntry:
    """Persist one reproducing crash input into the regression corpus and update
    the manifest. Content-addressed (sha256) so the same crash saved twice is one
    file; the manifest is idempotent on (finding_id, sha256)."""
    root = Path(corpus_root)
    inputs_dir = root / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    digest = hashlib.sha256(crash_input).hexdigest()
    fname = f"{digest[:16]}.bin"
    (inputs_dir / fname).write_bytes(crash_input)

    entry = RegressionEntry(
        finding_id=finding_id, cwe=cwe, sanitizer=sanitizer,
        input_file=f"inputs/{fname}", sha256=digest,
        reproduction_command=reproduction_command, note=note,
    )
    _append_manifest(root, entry)
    return entry


def _append_manifest(root: Path, entry: RegressionEntry) -> None:
    mf = root / "manifest.json"
    entries: list[dict] = []
    if mf.exists():
        try:
            entries = json.loads(mf.read_text()).get("entries", [])
        except (OSError, json.JSONDecodeError):
            entries = []
    # idempotent on (finding_id, sha256)
    key = (entry.finding_id, entry.sha256)
    entries = [e for e in entries
               if (e.get("finding_id"), e.get("sha256")) != key]
    entries.append(entry.to_dict())
    mf.write_text(json.dumps({"entries": entries}, indent=2))


def load_manifest(corpus_root: str | Path) -> list[RegressionEntry]:
    mf = Path(corpus_root) / "manifest.json"
    if not mf.exists():
        return []
    try:
        raw = json.loads(mf.read_text()).get("entries", [])
    except (OSError, json.JSONDecodeError):
        return []
    return [RegressionEntry(**e) for e in raw]


def replay_plan(corpus_root: str | Path, fuzz_target: str = "reattack") -> list[str]:
    """The per-PR replay commands — one `cargo fuzz run <t> <input>` per saved
    crash. A returning bug fails its line; a fixed one exits clean. Fast enough
    for CI (each is a single deterministic execution, not a fuzz campaign)."""
    root = Path(corpus_root)
    cmds: list[str] = []
    for e in load_manifest(root):
        cmds.append(f"cargo +nightly fuzz run {fuzz_target} {root / e.input_file}  "
                    f"# {e.finding_id} {e.cwe} ({e.sanitizer})")
    return cmds
