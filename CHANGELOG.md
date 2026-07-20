# Changelog

All notable changes to this fork. The upstream reference harness is unmaintained;
this file tracks the rust-in-peace fork only.

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
