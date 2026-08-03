# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Private-artifact denylist used by pre-commit and CI."""

from scripts.check_repo_hygiene import forbidden_reason


def test_private_artifacts_are_forbidden():
    assert forbidden_reason(".DS_Store")
    assert forbidden_reason("repo-disclosure/REPORT.md")
    assert forbidden_reason("DISCLOSURES.md")
    assert forbidden_reason("private-escrow/case/poc.bin")
    assert forbidden_reason("targets/rustls/JOURNAL.md")
    assert forbidden_reason("secrets.tkn")


def test_2026_08_hardening_private_artifacts_are_forbidden():
    # Root notes / ledgers
    assert forbidden_reason("findings-ledger.jsonl")
    assert forbidden_reason("HYPER-H2-FINDINGS.md")
    assert forbidden_reason("CHROMIUM-RUST-SURFACE-2026-07-29.md")
    assert forbidden_reason("POSTMORTEM-2026-07-20-disclosure-quality.md")
    # docs/ experiment corpora + raw dump
    assert forbidden_reason("docs/e13/E13-result.json")
    assert forbidden_reason("docs/e14/E14-recall.json")
    assert forbidden_reason("docs/writeups/protocol-defaults-at-seams.md")
    assert forbidden_reason("docs/sast-experiments.md")
    # targets/<crate>/ campaign research artifacts (matched by TYPE)
    assert forbidden_reason("targets/hyper/JOURNAL.md")
    assert forbidden_reason("targets/x509-parser/disclosure/pr/OPEN-PR.sh")
    assert forbidden_reason("targets/object/poc/harness.rs")
    assert forbidden_reason("targets/quick-xml/CONSOLIDATION.md")
    assert forbidden_reason("targets/hyper/BACKLOG-VERDICTS-2026-07-26.md")
    assert forbidden_reason("targets/ntex/reply-draft.local.md")


def test_normal_project_files_are_allowed():
    assert forbidden_reason("README.md") is None
    assert forbidden_reason("docs/case-studies/example.md") is None
    assert forbidden_reason("targets/rust-canary/config.yaml") is None
    # Demo targets ship THREAT_MODEL.md / capabilities.json — must NOT be flagged.
    assert forbidden_reason("targets/canary/THREAT_MODEL.md") is None
    assert forbidden_reason("targets/android-canary/capabilities.json") is None
    assert forbidden_reason("targets/dvra3-parser/config.yaml") is None
    # Tracked self-review + case studies stay allowed.
    assert forbidden_reason("self-review/FINDINGS.md") is None
    assert forbidden_reason("self-review/THREAT_MODEL.md") is None
    assert forbidden_reason("docs/sast-layer.md") is None
