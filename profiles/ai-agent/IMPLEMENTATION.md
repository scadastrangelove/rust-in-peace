# Implementation ledger — paused 2026-10-03

The user stopped execution work and requested that the work be retained as a
separate pack. No container builds, target execution, paid agent campaigns or
remote deployments are running for this work. Resume only on a new request.

## Saved work

| Artifact | State |
|---|---|
| `scan-extras.txt`, `fp-rules.txt` and supporting docs | Reusable static review pack; generalized, no campaign answer keys |
| `harness/ai_agent/contracts.py` and `schemas/` | Versioned JSON validation, strict types, bounded input, reference checks |
| `harness/ai_agent/capabilities.py` | Optional-engine decisions; unknown/unmapped observations keep research active |
| `harness/ai_agent/evidence.py` | Evidence consistency checks and scoped dispositions; imported JSON alone is not trusted replay |
| `harness/ai_agent/runtime.py` | Prototype bounded Docker victim/observer replay, controls and scheduled-trial accounting |
| `targets/ai-agent-canary/` | Synthetic service, Dockerfile, capability inventory and target contract; not built |
| `tests/fixtures/ai-agent-canary/` | Evaluator-only direct/deferred attack cases, public decoy and an unlisted-category case |
| `tests/test_ai_agent_contracts.py`, `tests/test_ai_agent_replay.py` | 45 local unit tests passed; replay tests use simulated labs, not Docker |
| `integration.patch` | Saved, unapplied `TargetConfig` integration; registry and lifecycle not wired |
| `frameworks.json` + `refresh_frameworks.py` | Evolving-standard tracker (track-don't-pin): sources + resolvers, current-version resolution, per-campaign provenance lock. 9 offline unit tests; live-verified 2026-10-03 (surfaced ASAMM v0.5.1→v0.5.1-draft, ATLAS v2026.09, CWE 4.20) |

Additional existing artifact/capability tests passed (20); the config-guard
checks passed alongside the contract tests. These are limited regression
checks, not a full test-suite run or proof of an executable profile.

## Remaining integration and verification

1. Review the prototype trust boundaries and evidence promotion. Bind scope,
   provenance, observation coverage and control adequacy to the authoritative
   replay; do not accept finder-supplied assessment JSON as trusted evidence.
2. Complete profile prompt/detector builders and `find/grade` integration.
   Preserve source arguments and unresolved candidates; verification needs a
   real entry and independent observation, not votes or legacy WITNESS strength.
3. Wire cause/path/witness identity through judge, dedup, aggregate, reports,
   scorecard and checkpoints. Do not inherit vote-based dynamic confirmation
   or the memory-exploitation report rubric.
4. Implement behavioral patch grading, legitimate-operation controls and
   independent reattack. Exit zero and missing sanitizer output are insufficient.
5. Implement live-agent/model access with isolated credentials, exact trial
   accounting, state reset and poisoned-evidence tests. The current adapter
   explicitly reports this mode unsupported.
6. Add selected optional engines with modality/provenance checks, native or
   guided fuzzing where relevant, and independently measured frontier search.
7. Build vulnerable/fixed/decoy canaries on the designated execution host;
   test forged evidence, observer failures, missing dependencies, delayed
   triggers, unknown capabilities and initially unlisted findings. Keep finder
   contexts and image layers free of answer keys and fixed/vulnerable labels.
8. Run the existing profile regressions and a real `find -> grade -> judge ->
   report -> patch/reattack -> scorecard` campaign before registering the profile
   as usable. Expand to held-out targets and measure incremental value.

## Execution host

The designated execution host is **Tamm = `<redacted-exec-host>`** (`sudo`),
confirmed by the user 2026-10-03 (earlier notes said `gorde` / "unresolved" — that
was wrong; this is the correct endpoint). Execution work is still **paused**: this
is recorded for resumption only; no remote files were deployed, no commands were
run there, and no containers were launched. Do not connect or build while paused.
The framework tracker (`refresh_frameworks.py`) is the one network tool here and
runs locally/read-only, outside any target sandbox.
