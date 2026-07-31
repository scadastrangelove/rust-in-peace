# Changelog

All notable changes to this fork. The upstream reference harness is unmaintained;
this file tracks the rust-in-peace fork only.

## Unreleased

### `sast-driven` — a fourth, isolated find mode (ADR-2)

- Added the static-analysis layer (`/sast-driven`, ADR-2). Static analysis enters as an *enumerator*, a
  *filtered candidate feed*, and *signature memory* — **never as a finding and never as a gate**;
  every SAST-origin candidate still goes through the unchanged union-of-N → 3-skeptic verify →
  independent-PoC path.
- Added `docker/sast/`: a **target-independent** tool image (OpenGrep 1.26.0, ast-grep 0.45.0,
  clippy + SARIF bridge, Dylint with trailofbits `general` pre-built, cargo-audit with an offline
  advisory DB, cargo-geiger), plus a two-phase runner whose split is the security contract — *fetch*
  has network but executes nothing, *analyze* executes the target's build scripts with
  `--network none`.
- Added the `/sast-driven` skill (`.claude/skills/` + `.agents/` twin): cells not hits, one
  reachability-judge agent per cell, and `PRUNE-LEDGER.md` as the per-rule yield record.
- **v1 runs every engine's DEFAULT rules and prunes from measured yield** rather than hand-picking
  rules up front; hits are tagged by engine, rule, and clippy lint *group* so pruning is per-group
  and data-driven. A prune verdict needs ≥3 crates.
- Added `corpus/pins.jsonl` (start of **W29**) and `rules/astgrep/` — five U1 *enumerators*, judged
  on completeness rather than precision.

### Rust release baseline

- Added hermetic CI on Python 3.11–3.13, repository-hygiene and Markdown-link
  checks, and removed unit-test dependence on a running Docker daemon.
- Wired the capability inventory into the Rust `run` boundary: logic-only
  targets skip the byte-crash track before auth/Docker and record the evidenced
  decision in `routing.json`.
- Separated machine `commit` refs from human `provenance_label` text and added a
  regression test that loads every shipped target config.
- Marked Android as an experimental research branch until witness strength is
  carried through the shared grade/aggregate/reattack lifecycle.
- Added fail-closed ignore, pre-commit, and CI checks for live disclosure and
  private-escrow artifacts.

## 0.3.0 — 2026-07-21

The "first-blood" release — cut after the fork's first upstream fixes landed
(disclosures across several real Rust crates) and the methodology that produced
them was made reproducible.

### Added
- **`/variant-scan` skill** — the three seed-diverse find passes (blind ∪
  threat-model-first ∪ CVE/history-seeded) + a 3-skeptic adversarial verify,
  promoted from a scratchpad workflow to a first-class, versioned skill
  (`.claude/skills/variant-scan/`), with the discipline gate that a "confirmed"
  vote is triage, not truth (read the verifier text + build an independent PoC).
- **Honesty gates wired into `grade`** (`harness/gates.py`): a `real` verdict now
  needs its premises evidenced — a dependency-behaviour claim needs a citation
  (L1), a reachability claim needs a where-checked trace (L3), a
  construction-only reproduction is UNVERIFIED until re-run through the real
  entry (L12), and an instrumentation-only crash (e.g. rust overflow-checks) must
  reproduce under the shipping build or it is `build_profile_gated` / R7 (L10).
  Gated findings route to CONTESTED/UNVERIFIED through the existing aggregate path.
- **`predisclose` stage** — an adversarial skeptical-maintainer review of a
  finding's four load-bearing claims (what/where, severity, fix, reachability)
  before disclosure.
- **Methodology docs**: `LESSONS.md` (L1–L37), `docs/variant-analysis.md`,
  `docs/variant-analysis-results.md` (redacted for coordinated disclosure),
  `IMPROVEMENTS.md` backlog.
- **Self-review hardening** (dogfood): sandbox runtime for the fuzz soak,
  credential redaction on transcripts, and a git-ref arg-injection guard.

### Changed
- **Default profile is now `rust`, not `cpp`** — a `config.yaml` without a
  `profile:` field resolves to `rust`; the retained C/C++ targets pin
  `profile: cpp` explicitly.

### Security / hygiene
- The repo is host-agnostic: no server name / IP / SSH user in tracked files —
  a fresh clone runs on any Docker host (`pip install -e .` →
  `./scripts/setup_sandbox.sh` → `vuln-pipeline run <target>`).
