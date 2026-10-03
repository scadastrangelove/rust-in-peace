# Implementation ledger

**2026-10-03 — integration layer landed (no execution).** The profile is now
**registered** (`harness/profiles.py`, as an *experimental* profile like
`android-app`): detector + find/grade/judge/report/patch prompt builders are wired,
`get_profile("ai-agent")` resolves, `detector_for_output` sniffs the `AIAGENT:`
header, and `integration.patch` is applied so `config.py` validates the target
contract (fail-closed) when `profile: ai-agent`. 60 offline unit tests pass and the
full 524-test suite still collects clean. **Still NOT a verified end-to-end run
target:** no container build, no `find→grade→…→scorecard` campaign, no live-agent,
and — critically — dynamic **confirmation is not wired**: a passed grade or an
aggregate vote is a *graded candidate*, not a confirmed finding. Confirmation must
come from `harness.ai_agent.runtime.replay` → `evidence.assess` (positive+negative
controls), which no stage calls yet. Container builds, paid campaigns and remote
deployment remain paused; resume those on a new request.

## Saved work

| Artifact | State |
|---|---|
| `scan-extras.txt`, `fp-rules.txt` and supporting docs | Reusable static review pack; generalized, no campaign answer keys |
| `harness/ai_agent/contracts.py` and `schemas/` | Versioned JSON validation, strict types, bounded input, reference checks |
| `harness/ai_agent/capabilities.py` | Optional-engine decisions; unknown/unmapped observations keep research active |
| `harness/ai_agent/evidence.py` | Evidence consistency checks and scoped dispositions; imported JSON alone is not trusted replay |
| `harness/ai_agent/runtime.py` | Prototype bounded Docker victim/observer replay, controls and scheduled-trial accounting |
| `targets/ai-agent-canary/` | Synthetic service, Dockerfile, capability inventory and target contract; **built + replay-verified on the host 2026-10-03** (image `ai-agent-canary:e2e`, 133MB) |
| `tests/fixtures/ai-agent-canary/` | Evaluator-only direct/deferred attack cases, public decoy and an unlisted-category case |
| `harness/ai_agent/detect.py` + `{find,grade,judge,report,patch}_prompt.py` | NEW 2026-10-03: detector surface (AIAGENT-header, dedup = invariant+component) + the 5 prompt builders; grade/find prompts defer confirmation to the operator replay, not self-report/votes |
| `harness/profiles.py` | NEW 2026-10-03: `_AI_AGENT` registered (experimental) + `AIAGENT:` sniff branch in `detector_for_output`; rust/cpp/android unaffected |
| `harness/config.py` | NEW 2026-10-03: `integration.patch` APPLIED — validates the target-contract (fail-closed) when `profile: ai-agent` |
| `tests/test_ai_agent_{contracts,replay,frameworks,profile}.py` | 60 offline unit tests pass; the replay path is ALSO verified on real Docker against the canary (see the e2e note below), not only simulated labs |
| `frameworks.json` + `refresh_frameworks.py` | Evolving-standard tracker (track-don't-pin): sources + resolvers, current-version resolution, per-campaign provenance lock. 9 offline unit tests; live-verified 2026-10-03 (surfaced ASAMM v0.5.1→v0.5.1-draft, ATLAS v2026.09, CWE 4.20) |

Test state: 60 ai-agent offline unit tests pass (contracts/replay/frameworks/
profile), the full 524-test suite collects clean, and the existing profile/dedup/
config/aggregate regressions (58) still pass.

**Dynamic replay e2e — verified on real Docker (host `<redacted-exec-host>`, 2026-10-03).**
Built the canary image and ran `runtime.replay` → `evidence.assess` against it (fresh
victim container per control and per attack, network=none, read-only, non-root,
positive+negative controls gating every trial):
- `vault-read` (real bug: `vault.read` with no owner token) → **confirmed, 3/3 trials**
  (independent replay observed the vault canary leak).
- `public-decoy` (a false positive: `public.info`) → **not_observed, 0/3** — the
  decoy is correctly NOT confirmed; controls passed, the attack did not leak.
- `delayed-export` (deferred worker trigger, 2-step full_chain) → **confirmed, 3/3**.
- `unlisted-category` → **confirmed, 3/3** (a finding outside the capability inventory
  is still caught).
~39s for all 4 × 3 trials × (4 controls + attack) fresh containers; zero leftover
victim containers afterward. This proves the trusted verifier is real and
discriminating — it is NOT yet called by the pipeline's grade/aggregate stages.

## Done 2026-10-03 (integration layer + replay e2e)

- Detector surface (`detect.py`) + the 5 prompt builders, emitting the exact tags
  each stage parses; dedup keyed on invariant+component (no `:line` to mangle).
- `_AI_AGENT` registered in `harness/profiles.py` (experimental) + `AIAGENT:` sniff;
  other profiles unaffected.
- `integration.patch` applied: `config.py` validates the target contract,
  fail-closed, when `profile: ai-agent`.
- Grade/find prompts explicitly defer dynamic confirmation to the operator replay.
- **Canary built and `runtime.replay`/`evidence.assess` verified end-to-end on real
  Docker** (confirmed the real bug, rejected the decoy — see the e2e note above). Reproducer: `profiles/ai-agent/e2e_replay.py`.

## Remaining integration and verification

1. **Confirmation wiring (the critical gap).** The trusted verifier itself is now
   proven on real Docker (replay e2e above); what remains is to CALL it from the
   pipeline: wire `grade`/`aggregate` to `harness.ai_agent.runtime.replay` →
   `evidence.assess` (positive+negative controls) instead of the self-grade, and
   give aggregate a non-vote confirmation path — a passed static grade or
   `votes>=2`/`passed_votes>=1` must NOT read as "confirmed" for this profile.
   Build the vulnerable/fixed/decoy canary set out to the e2e (currently one
   canary with a real-bug + decoy scenario). Do not inherit the vote model or the
   memory-exploitation report rubric. (Needs Docker/host for the real replay.)
2. Wire cause/path/witness identity through judge, dedup, reports, scorecard and
   checkpoints end to end (prompts are in place; the orchestration fields are not).
3. Behavioral patch grading + independent reattack: `patch_grade._t1_passes` and
   the reattack ladder are ASan-specific; add the behavioral oracle (attacker path
   no longer violates the invariant AND the legitimate-operation control still
   passes). Exit zero / missing sanitizer output are insufficient.
4. Live-agent/model access with isolated credentials, exact trial accounting, state
   reset and poisoned-evidence tests. The adapter currently reports this unsupported.
5. Optional engines with modality/provenance checks; native or guided fuzzing where
   relevant; independently measured frontier search.
6. Build vulnerable/fixed/decoy canaries on the execution host; test forged
   evidence, observer failures, missing dependencies, delayed triggers, unknown
   capabilities and initially unlisted findings. Keep finder contexts and image
   layers free of answer keys and fixed/vulnerable labels.
7. Run a real `find → grade → judge → report → patch/reattack → scorecard` campaign
   before calling the profile *usable* (it is registered-experimental, not usable).
   Expand to held-out targets and measure incremental value.

## Execution host

The designated execution host is **Tamm = `<redacted-exec-host>`** (`sudo`),
confirmed by the user 2026-10-03 (earlier notes said `gorde` / "unresolved" — that
was wrong; this is the correct endpoint). Execution work is still **paused**: this
is recorded for resumption only; no remote files were deployed, no commands were
run there, and no containers were launched. Do not connect or build while paused.
The framework tracker (`refresh_frameworks.py`) is the one network tool here and
runs locally/read-only, outside any target sandbox.
