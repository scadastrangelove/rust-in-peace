#!/usr/bin/env python3
"""Fail closed if private/security scratch artifacts enter the Git index.

`.gitignore` prevents the common `git add -A` accident.  This checker is the
second boundary: it examines every path known to Git (including staged new
files), so `git add -f` or an old tracked artifact still fails in pre-commit and
CI.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
IGNORE_SENTINELS = (
    ".DS_Store",
    "example-disclosure/REPORT.md",
    "DISCLOSURES.md",
    "DISCLOSURES.json",
    "DISCLOSURES.csv",
    "private-escrow/case/REPORT.md",
    "targets/rustls/JOURNAL.md",
    # 2026-08-03 hardening: these must stay gitignored so a removed rule is caught here too.
    "findings-ledger.jsonl",
    "HYPER-H2-FINDINGS.md",
    "docs/e13/E13-result.json",
    "docs/sast-experiments.md",
    "targets/hyper/JOURNAL.md",
    "rustls-aws-lc-ticketer-underflow/RESULTS.md",
)


def forbidden_reason(raw_path: str) -> str | None:
    path = PurePosixPath(raw_path)
    parts = path.parts
    if path.name == ".DS_Store":
        return "macOS metadata"
    # The private disclosure tracker in any format (DISCLOSURES.md/.json/.csv) at repo
    # root — it may name live, uncoordinated findings. NB: DISCLOSURES-PUBLIC.md (dash,
    # not dot) is the intentionally-public export and is not matched.
    if len(parts) == 1 and path.name.startswith("DISCLOSURES."):
        return "private campaign ledger"
    if parts and parts[0] in {"private-escrow", ".private-escrow"}:
        return "private escrow"
    if parts and parts[0].endswith("-disclosure"):
        return "live disclosure package"
    if len(parts) >= 2 and parts[:2] == ("targets", "rustls"):
        return "private rustls campaign material"
    # Root-level private research notes and ledgers (mirror the .gitignore hardening of 2026-08-03).
    if len(parts) == 1:
        name = path.name
        if name.startswith("findings-ledger."):
            return "private findings ledger"
        if name.endswith("-FINDINGS.md"):
            return "private campaign findings notes"
        if path.suffix == ".md" and (name.startswith("CHROMIUM-") or name.startswith("POSTMORTEM-")):
            return "private campaign material"
    # Private experiment corpora / raw dumps / pre-disclosure writeups under docs/.
    if parts[:2] in {("docs", "e13"), ("docs", "e14"), ("docs", "writeups")}:
        return "private experiment corpus"
    if len(parts) == 2 and parts[0] == "docs" and path.name == "sast-experiments.md":
        return "raw SAST experiment dump"
    # Real-OSS campaign research artifacts under targets/<crate>/. Matched by TYPE, never by a
    # crate allowlist: these types (JOURNAL/disclosure/poc/hardening/…) are absent from the tracked
    # demo targets, so this cannot fail on canary/alsa/russcan/…. THREAT_MODEL.md and
    # capabilities.json are DELIBERATELY not matched — the demo targets ship them, and the private
    # campaign copies rely on .gitignore (the primary boundary) instead.
    if len(parts) >= 3 and parts[0] == "targets":
        tail = set(parts[2:])
        name = path.name
        if tail & {"disclosure", "hardening", "rustsec", "poc"}:
            return "campaign disclosure/poc material"
        if name in {"JOURNAL.md", "CONSOLIDATION.md", "AB_COMPARISON.md",
                    "CVE-VARIANT-GROUNDTRUTH.md", "x509-lessons.md"} or "VERDICTS" in name:
            return "campaign research journal"
        if (name.endswith(".local.md") or name.startswith("reply-draft")
                or name.startswith("poc-") or name.startswith("harness-")):
            return "campaign scratch/poc"
    if path.suffix == ".tkn" or path.name in {"cc.tkn", ".rip-auth"}:
        return "credential material"
    return None


def git_paths() -> list[str]:
    proc = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [p.decode() for p in proc.stdout.split(b"\0") if p]


def missing_ignore_rules() -> list[str]:
    payload = "\0".join(IGNORE_SENTINELS) + "\0"
    proc = subprocess.run(
        ["git", "check-ignore", "--stdin", "-z"],
        cwd=ROOT,
        input=payload.encode(),
        capture_output=True,
        check=False,
    )
    ignored = {p.decode() for p in proc.stdout.split(b"\0") if p}
    return [path for path in IGNORE_SENTINELS if path not in ignored]


def main() -> int:
    forbidden = [
        (path, reason)
        for path in git_paths()
        if (reason := forbidden_reason(path)) is not None
    ]
    missing = missing_ignore_rules()

    for path, reason in forbidden:
        print(f"{path}: forbidden tracked path ({reason})")
    for path in missing:
        print(f".gitignore: does not protect sentinel path {path}")

    if forbidden or missing:
        print(
            f"repository hygiene failed: {len(forbidden)} forbidden path(s), "
            f"{len(missing)} missing ignore rule(s)",
            file=sys.stderr,
        )
        return 1
    print(f"Repository hygiene OK ({len(git_paths())} Git paths checked)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
