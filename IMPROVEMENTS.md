# IMPROVEMENTS — evidence-backed implementation backlog

This backlog is derived from the real-OSS campaigns summarized in
[`LESSONS.md`](LESSONS.md), now **L1–L49**. Priority is ROI (impact ÷ effort),
not headline severity. Each item names where it lands and a done-when check.
Older dated sections are retained as the decision history; the table immediately
below is the authoritative current release baseline.

Tag key: `[Ln]` = lesson it closes · `[camp]` = campaign that surfaced it.

## Current P0 release baseline (2026-07-24) — Rust primary

Android remains an experimental research branch. P0 makes the supported Rust
path reproducible and makes claims match wiring; it does not promote Android's
generic lifecycle to production.

| Release-baseline item | Status | Evidence / done-when |
|---|---|---|
| Hermetic unit suite | **implemented; locally green** | patch tests mock the sandbox boundary; proxy-env test clears ambient host state; full `python -m pytest -q` must remain 0-fail |
| CI on supported Python | **implemented** | `.github/workflows/ci.yml`, Python 3.11–3.13; compile + hygiene + links + full tests |
| Every shipped target config loads | **done** | `tests/test_config_commit_guard.py::test_all_shipped_target_configs_load`; machine `commit` is separated from `provenance_label` |
| Rust crash-track capability gate | **done** | `harness.cli._rust_crash_track_route`; logic-only Rust exits before auth/Docker and writes `routing.json`; `tests/test_cli_routing.py` |
| Documentation truthfulness | **done** | broken local links fixed; Rust default and actual capability consumers documented; Android explicitly experimental |
| Private-artifact containment | **done** | root ignore rules + `scripts/check_repo_hygiene.py` in pre-commit and CI; private escrow remains an external/access-controlled responsibility |

## Original campaign-gate implementation status

The P0 core + P1.4 shipped as **profile-agnostic** modules (keyed on the same
swappable nouns as `profiles.py`, not Rust-specific), each pure + unit-tested
(95 pure tests green, no cpp/rust regression). See `docs/extending.md` §
"Cross-cutting admissibility & profile-hygiene gates".

| Item | Status | Module / hook | Tests |
|------|--------|---------------|-------|
| P0.1 shipping-profile gate | **done** | `harness/build_profile.py` (registry keyed by profile: rust/cpp gated classes; android none) | `tests/test_build_profile.py` |
| P0.2 dep-citation gate | **done** | `harness/admissibility.py` (`VerdictClaim.dep_citation` → CONTESTED) | `tests/test_admissibility.py` |
| P0.3 soak = distinct sites | **done** | `harness/soak.py` + `scripts/run_fuzz_soak.sh` (dedup via profile detector) | `tests/test_soak.py` |
| P0.4 capability-gate crash track | **done, wired for Rust** | `CapabilityInventory.run_crash_track()` → `harness.cli._rust_crash_track_route()` + `routing.json` | `tests/test_capabilities.py`, `tests/test_cli_routing.py` |
| P0.5 flag construction repros | **done** | `harness/admissibility.py` (`HARNESS_DIRECT_CONSTRUCTION` → UNVERIFIED) | `tests/test_admissibility.py` |
| P1.4 where_checked forcing fn | **done** | `harness/admissibility.py` (`VerdictClaim.where_checked` → CONTESTED) | `tests/test_admissibility.py` |
| P0.6 verdicts-not-counts | **partial** | `soak.format_site_report` leads with sites; report template still to lead with dispositions | — |
| P1.1/P1.2 always-run seeded fuzz + auto-escalate | **spec+hooks** | prompt/skill-shaped: profile `find*` prompt + reattack bridge (L11) | — |
| P1.3 adversarial maintainer-review | **stage implemented** | `vuln-pipeline predisclose`; automatic enforcement before every outbound artifact remains open | `tests/test_predisclose.py` |

The pure gates are wired to plug into `grade`/triage additively (backward-compat,
same staging as `witness.py`); the remaining items are prompt/skill work on stages
a profile already provides.

## Landing/wiring status (updated 2026-07-24)

**Open majors:**
- **W2** — make `/variant-scan` a first-class `vuln-pipeline` CLI stage (today it's a skill a human drives).
- **W2b** — run the honesty gates end-to-end on a build host (W1b wired + unit-tested them; the live
  Docker/agent proof that a gated `disposition` lands in `result.json` hasn't been run).
- **W3** — remove model credentials from every target-execution environment.

### W1 — land and wire profile-hygiene modules  `[wiring]` — **DONE FOR THE RUST BASELINE 2026-07-24**
`admissibility.py`, `build_profile.py`, `soak.py`, `predisclose.py`, and their
grade hooks are present. P0.4 is now called at the Rust CLI boundary and records
an evidenced skip. `witness.py` and `android-app` remain in-tree as research
artifacts, but Android's strength-aware aggregate/reattack/patch lifecycle is
explicitly outside this completion claim.

### W1b — wire the honesty gates into a live stage  `[wiring]` — **DONE 2026-07-21**
Landing ≠ linked was the gap. Now closed:
- **`admissibility` + `build_profile` → wired into `grade`** via new `harness/gates.py`
  (`apply_gates`), called at the end of `run_grade`. It folds the gate result back into the
  `GraderVerdict` (new `disposition` + `gate_reason` fields, backward-compatible defaults): a gated
  finding gets `passed=False` → `status=crash_rejected` → the EXISTING `aggregate`/`dedup` path
  routes it to CONTESTED/dynamic-confirm, with **no change to aggregate.py**. The rust `grade_prompt`
  now elicits the inputs (`reproduced_under_shipping` for overflow-panics; `rests_on_dependency_
  behavior`/`dep_citation`; `claims_reachable`/`where_checked`; `harness_kind`). Additive: a grader
  that declares no premise trips no admissibility gate; `build_profile` only bites the
  instrumentation-gated overflow classes (all other classes pass straight through).
- **`soak` was ALREADY wired** — `scripts/run_fuzz_soak.sh` (on `main`) invokes
  `soak.enumerate_sites`/`format_site_report`/`done_line` from a `python3 -` heredoc for the
  `SOAK-DONE distinct_sites=N` line. (The earlier "not called" note was a python-import-graph
  artifact; it's shell-invoked.)
- **`predisclose`** — live CLI command, unchanged.
- **Verified:** `tests/test_gates.py` (10 tests) proves the fold — missing `dep_citation`→CONTESTED,
  construction-only→UNVERIFIED, un-re-tested overflow→build_profile_gated, clean→real, grader
  rejection stays rejected, verdict round-trips with the new fields; 335 pure tests green on `main`.
- **NOT verified here (needs the build host + agent auth):** a LIVE `grade` run where a real grader
  emits the tags and a gated `disposition` lands in `result.json` — the unit layer proves the fold,
  the end-to-end proof needs Docker. Also open: `triage` (a skill, not python) doesn't yet re-apply
  admissibility over its own re-derived verdicts — the grade-stage gate is the enforced one.

### W2 — make `/variant-scan` a first-class pipeline stage, not just a skill  `[wiring][L21/L25]`
The skill exists and is the documented recall front-end, but a human still drives it. Two rungs:
1. a `vuln-pipeline variant-scan <target>` CLI subcommand that runs the three passes + union +
   3-skeptic verify and writes `VARIANT-FINDINGS.json` in the `/triage` schema;
2. auto-invoke it (or at least the blind+TM passes) from the default `run` flow when a target
   has a `THREAT_MODEL.md` or a non-empty `capabilities.json` history list.
- **Done-when:** `vuln-pipeline variant-scan <crate>` reproduces a campaign's three-pass output
  without a hand-authored workflow script; the disposition-is-triage discipline gate (read
  verifier text + independent PoC before `real`) is enforced by the stage emitting
  `independently_verified: false` until a PoC/grade step flips it.

### W2b — live end-to-end verification of the honesty gates on a build host  `[verify][W1b]`
W1b wired admissibility + build_profile into `grade` and unit-tested the fold (`test_gates.py`), but
the LIVE path — a real grader in a Docker container emitting the premise tags, and a gated
`disposition` (CONTESTED / build_profile_gated / UNVERIFIED) actually landing in `result.json` and
routing through `aggregate` — has NOT been run (no Docker/agent on the dev Mac). Needs the build
host + agent auth.
- **Where:** a `vuln-pipeline run` on `rust-canary` (and one overflow-panic target) on the build host.
- **Done-when:** (a) a run whose grader omits `reproduced_under_shipping` on an overflow-panic shows
  `disposition=build_profile_gated` in `result.json` and the candidate is NOT confirmed; (b) a
  finding whose grader declares a dep premise without `dep_citation` shows `disposition=contested`;
  (c) a clean memory-safety crash still grades `real` (no false downgrade). Capture the three
  `result.json` snippets as the evidence this fires for real, not just in units.
- **Also:** `triage` (a skill, not python) does not yet re-apply admissibility over its own
  re-derived verdicts — decide whether the grade-stage gate is sufficient or triage needs its own.

### W3 — F1: keep the model-API credential out of the target-exec container  `[dogfood self-review · T2 · HIGH]`
The dogfood self-review (`self-review/{THREAT_MODEL,FINDINGS}.md`) found the pipeline dogfoods the
exact T2 its own threat model predicts: the Anthropic/Bedrock token sits in the env
(`Config.Env`) of the same container that runs untrusted target binaries — the find/grade/report
prompts tell the agent to execute `{binary_path}`, so an attacker binary reads `$ANTHROPIC_API_KEY`
and the egress proxy already allows `api.anthropic.com:443`. **F2/F3/F4 are fixed and now on `main`**
(commit landing this file: `run_fuzz_soak.sh` runsc+cap-drop, `harness/redact.py` token scrubbing,
`config._safe_git_ref` arg-injection guard — tests `test_redact.py`, `test_config_commit_guard.py`
green on `main`). **F1 is the remaining architectural one** and had lived only in
`self-review/FINDINGS.md`, not here.
- **Why no cheap fix:** the agent runs the untrusted binary via its own in-container Bash, so the
  token-holding container IS the exec container; `-e KEY` is already kept out of argv and mounts are
  `:ro`, but the env var itself is the leak.
- **Where:** route the in-container `claude -p` through the egress proxy as a **credential-injecting
  reverse proxy** — the proxy holds the token and adds `Authorization` on the way out; the container
  never sees the raw value. (`patch_grade.py` already sidesteps this with `auth=None` + `network=none`
  for the patch-grade stage; generalize that shape, or the proxy approach, to find/grade/report/recon/
  judge.)
- **Done-when:** no container that executes target code has a usable model credential in its env
  (`docker inspect` shows no token; a target binary that exfiltrates `env` gets nothing usable);
  the pipeline still authenticates to the model API.

---

## P0 — cheap, high-value, do first

### P0.1 Shipping-profile re-test gate at grade  `[L10][lopdf]`
The crash pipeline built with `overflow-checks=on`; all 5 autonomous "crashes" were
`panic_const_*_overflow` that don't reproduce under the target's shipping release profile. The grader
re-used the instrumented binary and graded build artifacts as `real`.
- **Where:** the grade stage (re-run each PoC against a shipping-profile build) + `run_fuzz_soak.sh`
  already sets `-Coverflow-checks=off` — extend the same discipline to the autonomous crash track.
- **Done-when:** every crash carries a `profile: {overflow_checks: bool}` field; a crash that only
  reproduces with checks-on is auto-tagged `R7 / overflow-checks-gated` and downgraded below `real`.
  Regression: the 5 x509 overflow "crashes" auto-downgrade without human intervention.

### P0.2 Cite-the-dependency structural gate  `[L1][L3][x509]`
The one wrong x509 verdict rested on an uncited, false claim about `asn1-rs` accept-behaviour.
- **Where:** triage schema + `harness/aggregate.py`. Add a required `dep_citation: "file:line"` field on
  any verdict (`real` **or** `false_positive`) whose load-bearing premise is a *dependency's*
  accept/reject/parse behaviour.
- **Done-when:** a dep-premise verdict with no citation is inadmissible → forced to `CONTESTED`. The
  x509 RSA over-claim is blocked by the gate rather than shipped.

### P0.3 Soak reports distinct SITES, not the ignore-crashes counter  `[L-ops][lopdf]`
`-ignore_crashes=1` yields a hit *counter* (~6.9k for content_decode), not an enumeration; the real
enumeration is repro-artifacts deduped by panic `file:line` (→ exactly 1 site). We only discovered this
by hand mid-run.
- **Where:** `run_fuzz_soak.sh` post-processing — add a `dedupe_sites.sh` that runs the production
  binary over `fuzz/artifacts/<tgt>/*` and groups by `panicked at <file:line>`.
- **Done-when:** `SOAK-DONE` line reads `distinct_sites=N (site → count)`, not just `crash: <counter>`.
  Also: copy artifacts out **periodically**, not only at `SOAK-DONE`, so mid-run triage works.

### P0.4 Capability-gate the byte-crash track  `[L4][x509]`
The crash track is blind on logic-heavy targets and trips cyber-safeguards for no yield.
- **Where:** `capabilities.json` routing (already machine-readable) → have the orchestrator **skip** the
  autonomous crash track when `has_untrusted_byte_surface=false`.
- **Done-when:** an x509-shaped target (logic-heavy, no raw byte entry) runs curated-static only; a
  lopdf-shaped target (byte-rich) runs both. Routing decision is logged.

### P0.5 Flag construction-based harness reproductions  `[L12][lopdf]`
The reattack bridge "reproduced" #2 by building the `Document` via the builder API, bypassing the
parser — the x509 false-reachability trap, one layer up inside the automation.
- **Where:** the find→fuzz / reattack bridge + scorecard.
- **Done-when:** any generated harness that constructs the target object directly (not via the parse
  entry) is emitted with `reachability: UNVERIFIED` and must be re-confirmed through the real parse
  entry (e.g. `load_mem` on crafted bytes) before the finding can be `real`.

### P0.6 Verdicts, not counts, in reports  `[L8][x509]`
- **Where:** report/consolidation template.
- **Done-when:** the scorecard leads with dispositions (real / CONTESTED / R7 / FP) and reachability,
  never a bare "N findings" headline.

---

## P1 — larger, high-value

### P1.1 Always-run seeded fuzz stage  `[L11][x509+lopdf]`
Across both campaigns cargo-fuzz / Miri / the reattack bridge were never run end-to-end unless a
Track-A crash forced it — yet when finally run, a seeded content_decode fuzz rediscovered the real bug
in ~2 min and the bridge auto-reproduced 3/4 statics.
- **Where:** pipeline — promote dynamic-fuzz to a first-class stage, **seeded from the corpus AND the
  static findings** (B→fuzz), gated only on `has_untrusted_byte_surface`, not on a prior crash.
- **Done-when:** every byte-surface target gets a fuzz pass by default; static findings are converted to
  seed inputs; the fuzz build uses the shipping profile (P0.1).

### P1.2 find-skill auto-escalation to a cargo-fuzz harness  `[L11][x509]`
On x509 the finder hand-crafted inputs for 93 min and never wrote a harness, though `fuzzing.md`'s
staircase prescribes it.
- **Where:** `profiles/rust/` find skill.
- **Done-when:** after N tool-calls without a candidate input, the skill emits a cargo-fuzz harness and
  runs it (enforce the staircase, don't just document it). Measured: x509-style sessions produce a
  harness artifact.

### P1.3 Adversarial maintainer-review as a pre-disclosure stage  `[L13][lopdf]` — **DONE 2026-07-20**
One skeptical-maintainer agent per finding (reject/downgrade/wontfix) before sending caught severity
inflation (Moderate→Low ×4), a wrong fix snippet, and two would-be dismissals — using the crate's own
code. `harness/prompts/maintainer_review_prompt.py` existed and was tested since the lopdf campaign
but was never called from any CLI stage — a real gap, found while auditing L15/L23/L31-L34 against
the actual pipeline code for what's disciplined-by-memory vs. coded.
- **Where:** new `predisclose` CLI command + `harness/predisclose.py` (`run_maintainer_review`),
  reading `reports/bug_NN/{report.json,patch.diff}` and writing `predisclose.json`.
- **Done-when:** each disclosure carries a maintainer-review record; severity + fix snippet are
  adversarially checked; reachability argument is hardened against the obvious rejection. ✅ (tests:
  `tests/test_predisclose.py`, `tests/test_artifacts.py::test_maintainer_review_verdict_roundtrip`).

### P1.5 The other three pre-disclosure checks — reverify-main, tracker-dedup, severity-baseline  `[L15/L32][L16/L23/L29/L33][L34]`
Three more disciplines proved out this session (rmp-serde+ttf-parser campaign) that are still pure
LESSONS.md prose, not code — same audit that found P1.3's gap:
1. **Reverify-main** — before a finding is called disclosure-ready, fresh-clone the target's current
   default branch and re-run the stored PoC/reproducer against it. Currently self-triggered discipline
   that keeps needing a user nudge (L32) rather than firing automatically.
2. **Tracker-scope check** — `gh search issues --repo <target>` (open+closed) by keyword; for any hit,
   `gh api repos/.../issues/{n}/timeline` → closing commit/PR → diff → structured NOVEL / DUPLICATE /
   RELATED-DISTINCT verdict (not just title-matching or open/closed state).
3. **Severity-baseline** — for complexity/throughput-class findings, a measured legitimate-use
   baseline (real-world data, not the PoC's own numbers) + attacker-cost-per-victim-cost ratio, instead
   of inheriting a finder agent's self-reported label; for crash-class findings, a CWE-mapped
   conventional rubric instead of a free-text guess (report.py's severity is currently pure agent
   self-report, see `report_prompt.py:103-139`).
- **Where:** all three belong inside the `predisclose` stage (P1.3's new home), not parallel modules —
  see `harness/predisclose.py`'s module docstring.
- **Done-when:** `predisclose.json` carries a `reverify_main` result, a `tracker_scope` verdict, and
  (for throughput-class findings) a `severity_baseline` measurement, alongside the existing
  maintainer-review block.
- **Naming note:** item 2's field is `tracker_scope` (checks the TARGET's own issue tracker for prior
  art, pre-filing). Don't confuse this with P1.7's `track` stage below, which monitors OUR OWN
  already-filed issues/PRs, post-filing. Same word, opposite direction and opposite side of filing —
  keep the field/stage names distinct in code and docs so a future reader doesn't conflate them.

### P1.6 `disclose` stage — mechanize the actual filing, but never unattended  `[manual practice, 2026-07-20]`
Filing the rmp-serde+ttf-parser campaign's 5 issues/5 PRs by hand this session worked, but was
error-prone in a way that's exactly the shape code should absorb: forking both repos, branching
per-fix off a fresh clone, applying each isolated diff, then `gh issue create`/`gh pr create` — one
mistake (the draft file's `TITLE:` line leaking into the issue body because the whole file was passed
as `--body-file` instead of stripping the title first) had to be caught and fixed by hand on issue #1
before it propagated to the other four. Sequencing also mattered: the CFF2 PR had to be created before
the avar/glyf-gvar/COLR PRs so their "see #N" cross-references had a real number to point at.
- **Where:** new `harness/disclose.py` + CLI `disclose` command, reading `predisclose.json` (must have
  an ACCEPT/DOWNGRADE verdict, not REJECT/WONTFIX) plus `patch.diff` per bug.
- **Safety-critical constraint, not optional:** this stage creates public content (fork, push, issue,
  PR) — squarely in the "explicit permission required" category from the operating rules, not
  something a pipeline should do unattended at the end of a batch run. Default behavior is **dry-run**:
  print the exact plan (repo, branch name, issue title+body, PR title+body, filing order and why) and
  stop. Only an explicit `--yes` (or an equivalent per-item confirmation) triggers the real `gh`/`git
  push` calls. No batch "file everything now" without that flag, ever.
- **Done-when:** dry-run output for a `bug_NN` matches what a human would write by hand (title, body,
  no leaked frontmatter, correct fix-based issue-vs-comment choice per the standing rule); `--yes`
  reproduces this session's actual filing steps exactly, including the ordering fix for cross-refs;
  writes a structured `reports/bug_NN/disclosure.json` (`{repo, issue_number, pr_number, branch,
  fork, filed_at}`) that P1.7 depends on.

### P1.7 `track` stage — post-filing status + the existing 14-day/90-day cadence  `[L27's cadence, manual practice]`
`DISCLOSURES.md`'s header already documents a cadence ("send → wait; first follow-up ~14 days if
silent; coordinate a fix/advisory on response; consider public disclosure/RustSec at ~90 days if
unaddressed") that today is followed entirely by memory — nothing checks whether a filed issue/PR
crossed a threshold, or diffs current status against last-known. Same failure shape as every other L32-
style gap: a documented discipline with no structural trigger.
- **Where:** new `harness/track.py` + CLI `track` command. Reads every `reports/*/bug_NN/
  disclosure.json` (P1.6's output) across a results tree (or a campaign-level list of them), polls `gh
  issue view`/`gh pr view` for state (open/closed/merged), comment count, and last-updated timestamp.
- **Done-when:** output flags each filed item as one of `awaiting_response` (< 14 days),
  `follow_up_due` (≥ 14 days, no maintainer reply), `escalation_due` (≥ 90 days, unaddressed — the
  RustSec-consideration point), `responded` (maintainer commented/reviewed — surface what they said),
  or `resolved` (merged/closed); optionally regenerates or cross-checks `DISCLOSURES.md`'s per-finding
  status lines against this instead of leaving them to drift from hand-edited prose.

### P1.4 Structural forcing function for reachability premises  `[L3][x509]`
A "smarter" review layer reproduced the same over-claim; only outside pressure caught it.
- **Where:** `harness/reachability.py` + triage schema.
- **Done-when:** every reachability claim carries a `where_checked` field (the parse path that proves
  reachability from untrusted input); a claim without it is `CONTESTED`, and an adversarial reviewer
  must sign off. Composes with P0.2 and P0.5.

---

## P2 — methodology / longer

### P2.1 Pair fuzzing with targeted-PoC synthesis on structure-heavy targets  `[L14][lopdf]`
Fuzzing found the shallow bug but structurally can't reach the deep ones (10⁵-deep `/Pages` chain;
nested empty-`/ColorSpace` XObject) — those needed hand PoCs.
- **Where:** a poc-synthesis stage seeded by *static structural* findings (deep recursion,
  empty-collection, decompression-bomb) rather than by the corpus.
- **Done-when:** a clean fuzz run on a structure-heavy target does NOT close the target; the static
  structural findings each get an auto-drafted targeted PoC to confirm/refute.

### P2.2 Fuzz/soak forensics & profile hygiene  `[L10][L-ops][lopdf]`
- Set `overflow-checks = false` explicitly in the fuzz profile so fuzzing doesn't manufacture L10
  artifacts.
- Detach long remote soaks with `nohup … & disown` / systemd unit (a backgrounded `ssh &` inside a
  tool call gets SIGHUP on return and kills the container — this bit us once).
- Treat `-max_total_time` as fuzz-time, not wall-clock; report coverage-saturation, not just budget %.
- **Done-when:** `run_fuzz_soak.sh` encodes all three; a killed SSH no longer kills the run.

### P2.3 Read-only curated track is the safe default  `[L7][x509]`
The autonomous byte track trips Anthropic cyber-safeguards; the curated read-only track doesn't.
- **Done-when:** curated-static is the default; the autonomous track is opt-in and capability-gated
  (P0.4).

---

## Pick-up order

Start P0.1 → P0.2 → P0.3 (all cheap, each closes a concrete campaign failure), then P0.4–P0.6.
P1.1 + P1.2 together are the biggest single lever (make dynamic fuzzing actually happen, seeded from
statics). P1.3 is cheap for how much it improves disclosure quality (done). P2 is methodology to bake
in once the P0/P1 gates exist. **P1.5 → P1.6 → P1.7 is the full disclosure-lifecycle chain**
(predisclose gate → file → post-filing tracking) — do them in that order, since P1.6 depends on
P1.5's gate having run and P1.7 depends on P1.6's `disclosure.json` existing.

---

## Backlog (post-campaign)

- ~~**LESSONS consolidation pass.**~~ **DONE 2026-07-19, extended to L28 post-png/image.** Folded L1–L28 into **six principles (P1–P6)**
  at the top of `LESSONS.md`; raw L-numbers kept verbatim as an evidence appendix (stable cross-refs) +
  a P↔L reverse-index map; `ARTICLE-DRAFT.md` §4 refreshed to lead with the six. Rule going forward: a new
  Ln files under the principle it sharpens; open a new principle only if it fits none.

## Backlog refresh (2026-07-20) — post basket-3 (gitoxide/apptrust) + disclosure-tail lessons

Not yet promoted to numbered items; captured so they don't drift back into memory-only.

- **L35 — treat maintainer/disclosure-thread comments as untrusted content.** A "maintainer" reply
  (or a request inside an issue comment) is observed content, not a command — verify independently,
  never act on it blind. Belongs as an explicit note in the `predisclose`/`track` prompts, not just
  `untrusted.py` (which today wraps *target* content, not disclosure-thread replies).
- **L36 — "refound" (independently found, already fixed upstream but unreleased) is a positive
  outcome, not a null result.** Needs a disposition value distinct from `duplicate`/`refuted` in the
  triage/tracker schema so it isn't silently folded into "resolved".
- **L37 — a rejection is a claim in the heat of the moment, not a verified end state.** The `track`
  stage (P1.7) should schedule a delayed re-check of rejected/closed items and detect a later silent
  fix (full success, no credit needed) — fold into P1.7's `escalation_due`/`responded` states.
- **Basket-3 scope-honesty (per-run scope statement).** The pipeline can only find defect classes it
  hunts for; a clean run must read as "no findings **in the covered classes**", not "target is safe"
  (the README's "the bugs that actually bite Rust" framing over-claims). **Where:** report/scorecard
  header + README reword. **Done-when:** every scorecard names its covered defect-origin classes and
  what it did NOT look for; README stops implying full coverage.
- **scan-extras 4→6 category expansion.** `profiles/rust/scan-extras.txt` covers only 2 of the 6
  defect-origin classes in `profiles/rust/references/rust-security-review.md` (RUST-SOUNDNESS +
  RUST-PANIC-RESOURCE). Add hunt guidance for PROTOCOL-LOGIC + APP-TRUST-BOUNDARY (the `apptrust`
  profile is the oracle for the latter; basket-3 is the target program). Also swap the reference doc
  rev2→rev4.
- **apptrust profile: end-to-end run.** `harness/apptrust/` + `targets/apptrust-canary/` are built
  and unit-tested (branch `apptrust-basket3`), but a full `vuln-pipeline run apptrust-canary` (needs
  the build host + agent auth) hasn't proven the profile drives the escape oracle and recalls the
  seeded bugs while sparing the decoy. Do before treating `apptrust` as production-ready.

## Backlog refresh (2026-07-22) — post Chromium/Skia browser-vendored campaign

First rust-in-peace finding in code that ships in a major browser (Chromium BMP Rust decoder,
`read_icc_profile` infallible alloc → renderer abort; filed public non-security, `crbug 537617321`).
Four new items surfaced by that campaign:

- **W4 — name the OOM-abort / uncontrolled-allocation oracle** `[L14][CWE-789][chromium]`. The
  infallible-alloc-DoS class (a `vec![0u8; attacker_u32]` that aborts via `handle_alloc_error` when it
  can't be satisfied) is both *confirmable* and *discoverable* with `cargo-fuzz -malloc_limit_mb=<cap>`
  (catches a single oversized malloc) + a `ulimit -v` wrapper (forces the abort on a 64-bit host,
  simulating a 32-bit/constrained renderer). Used this session to CONFIRM the BMP finding and to clear
  PNG (3.4M runs, peak RSS 384 MB, clean). **Where:** `profiles/rust/fuzzing.md` execution matrix +
  the `find→fuzz` CWE→oracle table. **Done-when:** an "OOM-abort / uncontrolled-allocation" row exists
  with the `-malloc_limit_mb` + `ulimit -v` invocation, and a CWE-789 finding auto-dispatches to it.
- **W5 — auto-inject the rust-in-peace credit into every report/disclosure body** `[[rust-in-peace-disclosure-credit]]`.
  The Chromium report was assembled and filed WITHOUT the standing credit line — caught only
  post-filing. A prose rule ("always credit") failed because the artifact was hand-assembled outside
  the templated path. **Where:** `harness/prompts/report_prompt.py` + `predisclose`. **Done-when:** a
  generated report/disclosure body contains the credit + repo link by construction; an artifact
  missing it is a lint failure before filing.
- **W6 — corpus-isolation affordance for comparison / A-B runs** `[L38]`. The Opus-vs-Sonnet A/B was
  contaminated because sub-agents read the on-disk plan + prior-run PoC. **Where:** the campaign
  runner. **Done-when:** a comparison run's SRC is a clean copy with a verified grep that no
  plan/results/PoC/notes file sits under any agent-readable path, and the run records `isolated: true`;
  a run that can't prove isolation is flagged recall-invalid.
- **W7 — new target class: browser-vendored Rust crates** `[basket-3 sibling]`. Rust crates vendored
  into a shipping browser (Chromium/Skia; later Firefox/Servo, etc.), where a crate-level bug becomes
  web-reachable. Selection rule = **L40** (hunt the fork/patch, not the unforked crate) + **L39**
  (trace to the browser's own caps before rating). Includes a watch-list re-check cadence: when
  Chromium moves ICO/JPEG/WebP from roadmap ("To do") to shipping, re-verify reachability (the
  build's enabled-features list is authoritative, per the §4.1 method) and re-tier. **Done-when:** a
  documented target-class entry + a scheduled roadmap-keyed reachability re-check.

## Backlog refresh (2026-07-23) — post TLS/protocol up-stack campaign (rustls/quinn/gitoxide/ciborium/actix-ntex)

The arc moved up-stack from byte-parsers to protocol/state-machine targets; **100% of the value came
from semantic bugs found by reasoning + differential review + harness-reuse PoC, with fuzzing unused**
(see `LESSONS.md` L42–L44). Five items to make that
routing deliberate and to re-arm fuzzing for the new layer.

- **W8 — target-layer router in the threat-model skill** `[L42][ADR-1][rustls]`. Classify every target
  as **data-format parser** / **protocol-state-machine** / **API-contract** and stamp it, so tool and
  bug-class selection is deliberate, not incidental. **Where:** `.claude/skills/threat-model/SKILL.md`
  (+ `.agents/` mirror) new Step 1.5; `bootstrap.md` writes the field. **Done-when:** every emitted
  `THREAT_MODEL.md` carries a `target_layer` + a per-layer hunt plan, and `bootstrap` picks fuzz-first
  vs invariant-first vs differential-first from it.
- **W9 — invariant-symmetry finder lens** `[L43]`. For every guard/check, locate its mirror across
  client↔server / send↔receive / offered↔accepted / one-param↔all-params; a control-asymmetry is the
  finding (rustls A/B). **Where:** `docs/lenses/protocol-invariant.md` + a fan-out review-brief in
  `vuln-scan`. **Done-when:** a protocol target's fan-out runs the mirror-walk lens and emits
  asymmetry candidates (guard-with-no-mirror) even absent a crash.
- **W10 — silent-failure differential oracle** `[L43]`. These bugs don't crash (rustls C:
  validated-then-discarded record); a crash oracle misses them. **Where:** the PoC/verify stage.
  **Done-when:** a candidate tagged "no crash, semantic" auto-scaffolds a **control-vs-attack** harness
  (identical construction, one variable = the suspected trigger) and rates it on the control/attack
  delta, not on a panic.
- **W11 — differential / stateful fuzz templates (bring fuzzing up-stack)** `[L42]`. Naive
  byte-mutation is the wrong tool for protocol layers; the right forms are **differential fuzzing**
  (impl-vs-oracle / impl-vs-impl) and **stateful/grammar fuzzing** that can build a valid handshake.
  **Where:** `profiles/rust/fuzzing.md` execution matrix + two new templates. **Done-when:** a
  differential-fuzz template (our-impl vs a reference impl/oracle, flag on behavioral divergence) and a
  stateful-handshake fuzzer stub exist, and a protocol target can invoke them from the `find→fuzz`
  table.
- **W12 — protocol-logic slice in the eval corpus** `[L44]`. rust-mizan measures memory-CVE recall —
  a class we largely stopped hunting; the metric no longer predicts value. **Where:** the rust-mizan
  eval corpus + scorer. **Done-when:** ≥8 seeded protocol-logic cases with ground truth
  (downgrade / enforcement-asymmetry / silent-loss / protocol-resource-growth) exist and recall is
  reported **per bug-class**, so parser-recall and protocol-recall are distinct numbers.

## Backlog refresh (2026-07-27) — post h2/hyper/Deno HTTP-stack campaign

**Status check on W8–W12 before adding to them**, verified against the actual tree rather than
memory: **W8 done** (the target-layer classification table is real and wired in
`.claude/skills/threat-model/SKILL.md`); **W9 done** (`docs/lenses/protocol-invariant.md` exists,
referenced from the routing table); **W10 spec'd but not tooled** — the skill *instructs* flagging
silent-failure candidates for "a control-vs-attack oracle," but no reusable harness exists anywhere in
the tree; every campaign since hand-built its own from scratch (h2's GOAWAY-reason diagnostic, rustls's
A/B PoC, actix-busyloop's `/proc/self/stat` CPU measurement); **W11 not started** — no
differential/stateful fuzz template exists anywhere; **W12 status unchecked this pass** — rust-mizan
lives outside this repo (`~/Documents/rust-mizan`).

The h2/hyper/rustls/Deno/actix/ntex arc (`LESSONS.md` L45–L48) is a second full protocol-layer
campaign since W8–W12 were written. It reconfirms some of that backlog's assumptions while surfacing
gaps the first arc didn't: a fix L45 already fully specified but that never got built, an oracle-
building tax paid fresh on every campaign, a manual audit technique that should be a script, an
eligibility check now done by hand every time, and (L49) a disclosure-tracking burden with no
automation at all.

- **W13 — target-ORDERING rule for layered ecosystems (the L45 fix, never landed)** `[L45][ADR-1]`.
  L45 already specifies the change and it was never implemented — verified via
  `grep -n "ship\|integration layer\|hunt.*first\|ordering" .claude/skills/threat-model/SKILL.md`: no
  hits beyond an unrelated release-diff line. Not hypothetical: it caused a real, admitted mistake this
  session (h2 hunted before hyper, wasting effort rating a finding-cluster the shipping integration
  layer had already neutralized). **Where:** threat-model Step 1.5, immediately after the
  existing layer-classification table — add a known-stack ordering table (`httparse`/`h2` ← `hyper` ←
  axum/reqwest/tonic; `asn1`/`x509` ← `rustls` ← …) naming the shipping integration layer and
  instructing hunting it first, with inner crates treated as reachability-gated by it. **Done-when:** a
  multi-layer target's `THREAT_MODEL.md` names the shipping layer explicitly and the hunt plan visits
  it before any crate it wraps.
- **W14 — promote W10 from spec to a reusable oracle scaffold** `[L46][L43]`. Three campaigns in a row
  hand-built the same shape of tool: a differential/protocol-signal harness answering "did the attack
  arm actually behave differently from the control arm," each time from scratch. L46 is the sharpest
  instance — an RSS-based differential on h2 initially read as a REFUTAL (both arms grew) until a
  protocol-level oracle (GOAWAY reason, not memory) showed the truth; the harness's own buffers had
  confounded the raw metric. **Where:** the PoC/verify stage, per W10's original spec — the concrete
  unit to build is a small library of oracle patterns (protocol-signal diff, control-vs-attack
  construction, spec-vs-impl divergence) a campaign imports instead of re-deriving. **Done-when:** a
  new protocol campaign's PoC stage starts from a library import, not a blank file.
- **W15 — ecosystem-seam-pass as a script, not a manual campaign** `[L47]`. The h2 push-panic audit
  (`h2-consumer-push-audit/`) hand-classified the top-100 `h2` reverse dependencies from crates.io —
  dozens of scratchpad clones and hand-built PoCs, run once, thrown away. L47's own "Change" already
  names the four-way classification (protected-by-integration / direct-default-inherited /
  explicitly-disabled / public-path-blocked); nothing mechanizes it. **Where:** a new
  `scripts/ecosystem_seam_scan.py <crate> <pattern-to-check>` — pulls the crates.io reverse-dependency
  page, greps each candidate's published tarball for the pattern (e.g. an explicit safety call),
  buckets by the four classes, and emits a markdown table ready to drop into a finding writeup; dynamic
  verification of the flagged bucket stays a human/agent step. **Done-when:** the next high-fan-out
  protocol finding runs the script instead of a bespoke clone-and-grep loop.
- **W16 — automate the L48 published-exposure gate** `[L48]`. Caught by hand this session: downloaded
  two crates.io tarballs, `tar xzf`'d them, and grepped/diffed manually to discover the ntex regression
  never shipped in any published release — a RustSec-queue near-miss that the existing Attribution and
  Timing gates both passed. **Where:** `scripts/check_published_exposure.py <crate> <pre-fix-version>
  <pattern-or-file:line>` — fetches the named pre-fix version's tarball from crates.io and greps for
  the vulnerable shape, reporting present/absent before anything is queued. **Done-when:** the RustSec
  queue section of the disclosure tracker requires this script's output — not just attribution plus a
  release timestamp — before an item is marked ready-to-file.
- **W17 — re-evaluate W11's priority against two-arc evidence, don't silently carry it forward**
  `[L42][L43]`. W11 (differential/stateful fuzz templates) has now gone unbuilt and untried across
  *two* full protocol-layer campaigns (rustls/quinn/gitoxide/ciborium/actix-ntex, then
  h2/hyper/rustls/Deno/actix/ntex again) — both delivered 100% of their value from reasoning plus
  differential review plus hand-built dynamic PoC, zero from fuzzing of any kind. That is not evidence
  fuzzing can't work up-stack; it is evidence the manual techniques have so far been sufficient enough
  that building fuzz tooling was never actually forced. Carrying W11 forward at its original priority
  without re-examining that is exactly the backlog drift this file's ROI-first ordering exists to
  prevent. **Where:** this file's own priority ordering. **Done-when:** either a concrete near-miss is
  identified where a differential/stateful fuzzer would have found something the manual lenses
  (W9/W10) missed — promoting W11 back up with real justification — or W11 is explicitly re-tagged
  speculative/lower-priority pending that evidence, rather than sitting at its original rank by inertia.
- **W18 — `DISCLOSURES.json` as the single source of truth; stop hand-maintaining scorecard
  arithmetic** `[L49]`. The same status change (e.g. the Deno GHSA closing) currently has to be
  propagated by hand across four files — `DISCLOSURES.md`, a per-campaign findings file,
  `DISCLOSURES.json`/`.csv`, and `DISCLOSURES-PUBLIC.md` — and an error in any one of the four stays
  invisible until the next full sweep. **Where:** promote `DISCLOSURES.json` from an occasional export
  to the canonical record; add `scripts/render_disclosures.py` to regenerate `DISCLOSURES.md`'s
  scorecard table and `DISCLOSURES-PUBLIC.md`'s summary stats from it, so the arithmetic is computed
  once and rendered everywhere instead of hand-copied per file. **Done-when:** the scorecard table
  carries a generated-marker and a pre-commit/CI check fails if it drifts from `DISCLOSURES.json`.
- **W19 — a `recheck` script for the live-GitHub sweep, not a hand-written loop each time** `[L49]`.
  The "check every tracked issue/PR/GHSA against live GitHub state" sweep ran three separate times this
  session, each as a freshly hand-written bash loop re-deriving which items are still non-terminal.
  **Where:** `scripts/recheck_disclosures.py` — reads `DISCLOSURES.json`, live-checks every item not
  already in a terminal state via `gh issue view`/`gh pr view`/`gh api .../security-advisories/{id}`,
  and reports only what changed since the last recorded `last_github_update`. **Done-when:** "check for
  changes" is one command, not a multi-tool-call manual sweep, and its diff output is what drives
  `DISCLOSURES.md` updates rather than a human re-deriving the item list from memory each time.
- **W20 — guard-to-sink coverage lens** `[h2 trailers]`. The existing mirror walk says “send ↔ receive,”
  but it does not force an inventory of every way a semantically equivalent object reaches the wire.
  `check_headers` guarded three outbound `HEADERS` constructors and missed `send_trailers`, despite all
  four eventually queuing the same frame. **Where:** a protocol finder pass that inventories a guard,
  the semantic object it protects, and every sink/constructor for that object; report guarded and
  unguarded routes side by side. **Done-when:** given `check_headers`, the pass emits a coverage table
  for every `Headers` egress path and marks the trailer route as an unguarded candidate without relying
  on an agent to notice the missing call by chance.
- **W21 — resource-accounting unit-mismatch lens** `[embargoed HTTP/2 DoS]`. A resource guard charged
  one unit (e.g. bytes) while the victim structure retained another (e.g. queued entries); items that
  are free in the charged unit therefore accumulate without bound in the storage unit. This pattern is
  broader than HTTP/2: empty records, duplicate control messages, and zero-work state transitions evade
  byte/time quotas while growing a count- or allocation-based structure. **Where:** a static pass over
  queues, maps, stream tables, and allocation sites that traces their admission charge and emits a
  ledger `{attacker unit, charged unit, retained unit, zero/cheap value}`. **Done-when:** a target with
  a `push_back` following a zero-valued charge produces a candidate automatically; the search is
  not limited to explicit `len == 0` text matches.
- **W22 — temporal re-entry / double-application lens** `[embargoed HTTP/2 panic]`. A state-machine
  assertion tripped not from a missing client/server mirror but from one valid transition being
  classified as “initial” twice. The finder needs to enumerate **state × message class ×
  repetition**, especially around `initial`, `counted`, `opened`, `reserved`, `end_stream`, and
  `*_once` flags. **Where:** protocol-state-machine review brief plus a small transition-table extractor
  from match arms/error enums. For each state-changing handler, ask whether applying a valid peer event
  twice preserves its admission predicate while duplicating a counter, queue entry, or side effect.
  **Done-when:** the generated candidate table highlights repeated-event transitions before any
  manual PoC is written, and also lists the counter/assertion reached on the second application.
- **W23 — protocol-translation product matrix** `[h2 trailers][hyper h1]`. The generic “h1 ↔ h2” axis
  is too coarse. The missed paths sit in the product of **ingress protocol × egress protocol × message
  position × role**: head vs trailer, client vs server/proxy, normal body vs CONNECT/Upgrade. A rule
  enforced on an h1 head or h2 ingress says little about h1→h2 trailer forwarding. **Where:** the
  protocol finder emits a finite matrix for every normalizer/forwarder/encoder and attaches each
  security-relevant field rule to its covered cells. **Done-when:** for connection-specific headers the
  matrix makes `h1 ingress → h2 egress → trailer → proxy` an uncovered high-priority cell, rather than
  treating a main-head guard as coverage of the whole message.
- **W24 — configuration-default reachability pass** `[embargoed HTTP/2 finding][L45/L47]`. Search should not
  discover a deep core bug and only later learn that the shipping stack disables it. Before ranking a
  protocol candidate, trace each security-relevant `Builder`/`Option` default through the public
  constructors of the shipping integrator and direct-client APIs. This both de-prioritizes protected
  core paths and elevates dangerous defaults inherited by direct consumers. **Where:** target
  reconnaissance, after the shipping-layer inventory and before deep finder fan-out. **Done-when:** the
  pass records each security-relevant default and the integrator's override, and labels
  dangerous-default-inherited paths as “direct-consumer surface” at discovery time rather than after
  the full core audit.
- **W25 — semantic test-matrix gap miner** `[h2 trailers][embargoed HTTP/2]`. Existing tests often
  prove a rule for the common cell and leave the rare semantic dimension untested: main headers but not
  trailers, single vs repeated control frames, non-empty vs empty payloads, ordinary requests but
  CONNECT. Mine test names/fixtures and handler call sites into a matrix, then feed uncovered cells back
  as finder tasks. **Where:** a pre-fan-out static stage for protocol targets. **Done-when:** it emits
  actionable cells such as `send_trailers × connection-header` (and analogous rare-dimension cells for
  other protocol handlers); a candidate is only dismissed after its missing test cell has
  been reviewed, not because an adjacent happy-path test exists.

> **Why these five and not five others (L51).** Mirror-walk is a rank-1, pairwise-semantic projection
> (guard on side A ↔ side A'); W20–W25 each restore a dimension it collapses — N-ary sink coverage
> (W20), three-way resource units (W21), temporal repetition (W22), the `ingress×egress×position×role`
> product (W23), and the orthogonal test-coverage signal (W25). The finder's coverage = the set of
> dimensions it enumerates, not the bugs it happens to notice.

- **W26 — project-type-conditional finder emphasis packs (shared lens library + per-type hints)**
  `[L51][ADR-1]`. W20–W25 are the PROTOCOL-STATE-MACHINE pack; the lenses recur across target types with
  different instantiations (W21 unit-mismatch IS the decompression-bomb lens IS the parser's
  alloc-from-length lens). So the right shape is a shared lens LIBRARY plus a per-project-type EMPHASIS
  vector injected into the finder/threat-model brief as ADDITIVE hints ("attend to…", never "only look
  for…", so the unexpected isn't narrowed away). Packs grounded in our campaigns:
  - protocol codec / state machine (h2, quinn) → W20 guard→sink, W21 unit-mismatch, W22 temporal, W25 test-gap
  - integrator / proxy (hyper, actix, ntex) → W23 translation-matrix, W24 default-reachability, TE/CL reconciliation
  - parser / deserializer (x509, lopdf, image, ciborium) → resource-limits (depth/recursion), alloc-from-length, differential-vs-spec, unsafe-on-bytes
  - crypto / TLS (rustls) → invariant-symmetry (offered↔accepted), handshake-ordering, downgrade, panic-on-attacker-input
  - compression (miniz, zune) → W21 unit-mismatch on ratio (bombs), output-size caps
  Mirror-walk stays the baseline for all; the pack adds weighted attention. **Where:** ADR-1 Step 1.5 —
  the router already classifies the layer; extend it to stamp the project-type and inject the pack.
  **Done-when:** a target's `THREAT_MODEL.md` records its project-type + emphasis pack and the finder
  brief carries those hints; a parser is not fanned out with protocol-codec hints, or vice versa.
- **W27 — the next two collapsed-dimension lenses: value-range guard + allocation-provenance** `[L51]`.
  L51's projection view predicts the lenses beyond W20–W25: (a) VALUE-RANGE — a guard is PRESENT but with
  the wrong threshold/boundary (off-by-one, `<` vs `<=`, missing upper bound); h2 #909 (panic at >24,576
  header fields) is this class, and our pairwise lens is shaped not to see it. (b) ALLOCATION-PROVENANCE —
  a length/count from attacker bytes flows into an allocation or loop bound without a cap (parse /
  decompression bombs). **Where:** two more finder passes in the protocol/parser packs (W26).
  **Done-when:** value-range emits a candidate for every numeric guard whose bound is attacker-influenced;
  allocation-provenance emits one for every `with_capacity`/`reserve`/loop-bound fed by a parsed length.
- **W28 — SAST as (a) the lens ENGINE and (b) a reachability-filtered coverage feed** `[L51][W17]`. Two
  roles for a Rust SAST pass, both grounded in the fuzz-coverage gap: (a) ENGINE — several lenses ARE
  SAST rules: W20 guard→sink is a taint rule ("sink reached without its guard on the path"); W27
  value-range/alloc-provenance are pattern rules. Writing them as rules (**ast-grep** has first-class
  Rust; semgrep via tree-sitter; dylint for typed lints) makes the static lenses reusable, deterministic,
  low-noise — instead of a bespoke AST-walker per target. (b) COVERAGE FEED — a broad pass (community
  packs + clippy security lints + `cargo-geiger` for the unsafe surface + `rudra`/`MIRAI` for
  unsafe-memory-safety and panic/overflow). Noisy by design; tame it with a MANDATORY reachability-filter
  (drop every hit not on an attacker-reachable path per the threat model) + cluster-by-class, and feed
  only survivor clusters to the finder as candidate cells. **Raw SAST output never becomes a finding** —
  it becomes a candidate that runs the normal find→verify. The noise is the price of a cheap STATIC
  coverage instrument (vs the expensive dynamic one); reachability-filtering + clustering + the verify
  gate make it payable, and it partially covers the resource/panic class W17's fuzzing gap leaves open.
  **Where:** a parallel "broad-net" lens in recon, distinct from the targeted packs; output = candidate
  cells. **Done-when:** W20/W21/W27 ship as committed rule files, and a broad-pass run emits a
  reachability-filtered, class-clustered candidate list with the count of hits DROPPED by the filter
  logged (no silent truncation).
  → **DESIGNED 2026-07-28 (`/sast-driven`, ADR-2).** The design splits W28's two roles into four (U1 enumerator / U2 candidate feed / U3
  signature memory / U4 negative memory), each with its own promotion gate, and adds the tool tiering
  that W28 didn't have: **Tier-P** (pattern engines — no build, host-safe) vs **Tier-C** (clippy /
  Dylint / MIRAI — a compile executes the target's `build.rs` and proc-macros, so container-only).
  W29–W31 below are the work items it produces; run **W29** and **experiment E1** before building any
  of it.
- **W29 — the labeled corpus: `corpus/findings.jsonl` + `corpus/pins.jsonl`** `[ADR-2][prerequisite]`.
  Every measurement in the SAST design — rule scoring, promotion gates, retro-scan, and experiment E1 —
  needs a ground truth we do not yet have in machine-readable form. The inputs all exist: `DISCLOSURES.json`
  (56 findings, but **no `file:line`, no pinned commit, no fix commit**), the `*-disclosure/` packages
  (which carry the exact site and mechanism), `targets/*/THREAT_MODEL.md` (the `Pin:` sha + the ADR-1
  layer stamp), and the campaign JOURNALs (which hold the **refuted** candidates — half the value per
  the variant-analysis "seed is a pattern from ANY disposition" rule, and currently machine-readable
  nowhere). **Done-when:** one row per finding with `{finding_id, crate, repo, commit, file, line,
  symbol, class, lens, disposition, fix_commit, advisory}`, a `(repo, commit)` clone cache in the shape
  `novelty.py` already uses, and the refuted set included. This is a few hours of extraction and it is
  what makes the rest falsifiable — without it the rule pack is unfalsifiable and the design is prose.
- **W30 — the signature-expansion loop: distill → score → promote → retro-scan** `[ADR-2][P7]`. The
  mechanism that makes a finding compound instead of being a one-shot asset. Four commands
  (`distill` / `rules score` / `rules promote` / `rules retro`) plus three `feedback.py` edges —
  **P8a** `candidate(any disposition) → draft rule`, **P8b** `new active rule → retro-scan the corpus`,
  **P8c** `refuted → suppression`. Two non-negotiable properties: **every rule is born with a test**
  (its seed site must match; its *guarded siblings* must not — this is what forces the rule to encode
  the guard rather than just the dangerous shape), and **two tracks** (`shadow` feeds cells only,
  `active` may produce candidates), promoted by measured precision — or, for enumerators, measured
  *completeness*, since an enumerator with 200 hits is a healthy worklist and a candidate rule with 200
  hits is broken. **Done-when:** one net-new candidate surfaces via retro-scan in a target we already
  finished. That single event is the proof the loop compounds; until it happens the loop is unproven.
- **W31 — experiment E1: retro-validate the SAST premise on our own campaigns** `[ADR-2][falsifier]`.
  Before building P1–P3 of the design, write 6–8 rules encoding W20/W21/W27 plus four already-disclosed
  patterns, run them against the pinned commits of h2 / hyper / rustls / quick-xml / lopdf / object, and
  measure three things: (1) **U2 recall** — do they re-find our own confirmed findings? *Predicted yes
  for the parser/arith/alloc class, **no** for every protocol-logic finding; a positive on the protocol
  ones should make us suspect the rule, not celebrate.* (2) **U1 completeness** — does the enumerator
  return the sites the mirror-walk actually used, **and what does it return that the walk never
  visited?** That residue is the first direct measurement of the L51 blind spot. (3) **Noise** —
  hits/kloc pre- and post-filter, per tier. **Done-when:** the three numbers are recorded. A clean
  negative on (1) with a positive on (2) is the expected, useful result — it says the layer's role is
  enumerator + memory, not finder, and the build should be trimmed to that.
- **W32 — the `vuln-pipeline-sast` tool image** `[ADR-2 §8.3]` — **BUILT 2026-07-28** (`docker/sast/`,
  built on the x86_64 box; the laptop is arm64 with ~11 GiB free, so the image lives where the corpus
  runs). Shipped alongside it: the `/sast-driven` skill (+ `.agents` twin), `rules/astgrep/` with five
  U1 enumerators, `corpus/pins.jsonl` (8 crates, campaign pins where they exist), and the two-phase
  `sast-scan.sh` / `run-batch.sh` drivers. Original rationale below. **Do this first; it is the enabler.**
  None of OpenGrep / ast-grep / Dylint / cargo-geiger is installed on a typical operator host, so
  nothing above can even be measured until the toolchain is packaged. One **target-independent** image
  (every existing image is per-target), built by `agent_image.py`'s shared-base idiom, with the target
  source arriving as a read-only bind mount — which `docker_ops.run(mounts=…)` already appends `:ro`
  to and `exec_sh` already drives. Runs under gVisor with `--network none`; the crate's deps come from
  an orchestrator-side `cargo fetch --locked` (downloads, does **not** build → no `build.rs` executes
  on the host) mounted read-only, so the container can run `--offline`. Both invariants hold: untrusted
  code never runs outside the sandbox, the sandbox never gets network. Keep the high-FP nightly tools
  (MIRAI, lockbud) in a separate shadow-track image and use upstream's frozen Rudra image as-is rather
  than bloating the default. CodeQL is **not** baked in — the image exposes an `/opt/codeql` mount
  point so a licensed operator brings their own CLI, which enforces the BYOL contract by packaging
  instead of by policy. **Done-when:** `--smoke` runs every bundled engine over `targets/rust-canary`
  in-container, emits SARIF per engine, `docker inspect` confirms `runtime=runsc` + `NetworkMode=none`,
  and the run manifest records the `image_digest` — which is half the score key `(corpus_rev,
  image_digest, rule_pack_rev)` that makes "did the rule pack improve recall?" answerable.

## Backlog refresh (2026-07-29) — post `rust-sast-implementation-guide.md` review

An external proposal (`~/Documents/rust-sast-implementation-guide.md`, rev 1.0, consolidated from
three RustSec/CVE surveys) was read against what we have actually built and measured. **Status of the
source: proposal, nothing deployed, and its own Appendix B marks 9 of its RUSTSEC/CVE citations
unverified.** So the rule applied here was: take its *structure*, verify its *content* through our own
corpus. Four items worth taking, one explicitly rejected.

- **W33 — harvest `rustsec/advisory-db` into a paired TP/TN corpus** `[guide §3][enabler]` — **DONE 2026-07-29: 628 paired fixtures, and the result is a NEGATIVE one** (journal E7/E7b/E7c). On real ecosystem ground truth the pack does not locate fix sites better than chance (0.97x on the 125 tight-fix pairs, with a corrected null); class-routing scores below chance. Root cause is density, not aim — a median of 396 hits per crate. The corpus did exactly its job: every earlier score came from our own 58 findings, the set the rules were built from. The single
  highest-leverage item in the document, and it attacks a weakness we measured ourselves. Every
  advisory carries the crate and its `patched` range, so `TP := crate@(highest version < patched)` /
  `TN := crate@(lowest version in patched)` builds mechanically, at scale, on **real** code. The
  discrimination test it enables is the point: *a rule that fires on BOTH versions is not detecting the
  vulnerability, it is detecting the crate's style* — invisible without the paired corpus. This is the
  same discipline we hand-built for DVRA (the hardened twin in the same file, enforced by
  `scripts/rule_test.py`) scaled from 3 synthetic apps to the whole ecosystem, and it targets
  **systematic weakness #6** in `docs/finding-class-map.md` head-on: rules developed on DVRA scored
  **0 across 12 real crates** — not low precision, *zero coverage* — because a rule inherits the shape
  of the corpus it was written against. Harvest `informational = "unsound"` advisories too: they carry
  no CVE and no CVSS, and for the soundness classes (W36) they are the bulk of the labelled data.
  Free side effect the guide notes itself: the harvest parses exactly the files that would verify its
  own unverified advisory IDs, so verification costs nothing once this runs. **Done-when:**
  `corpus/tp/<RUSTSEC-ID>/` + `corpus/tn/<RUSTSEC-ID>/` exist, and all 54 ast-grep rules plus the 8
  CodeQL queries have a recorded fire/no-fire pair per fixture — with "fires on both" counted as a
  **failure**, not a pass.
- **W34 — re-grade detectability per (class × ENGINE), not per class** `[guide §1.1][measured]` —
  **DONE 2026-07-29** (`docs/finding-class-map.md` § *Grade is a property of (class × ENGINE)*,
  journal entry E8). **7 of 9 classes grade differently across engines, four inverting outright**
  (R under one, N under the other). Two things the class-level grade could not express: no engine
  dominates (blind spots follow from what each one *represents*, so routing moves them and rule work
  does not), and **an N is only N relative to the instruments in hand** — unwind-safety was
  reasoning-only until E6 wired Miri, then became the most decisively gradeable class in the set. One
  cell is deliberately left `unmeasured` (limit-bypass under CodeQL, the corpus's most common class):
  it would be the most valuable entry in the grid, it has not been run, and recording it blank rather
  than inferring it is the point. Original rationale below. The
  guide states it and our CodeQL A/B proves it: unguarded-pop is candidate-grade in ast-grep and
  precise in CodeQL; serde re-entrancy is precise in ast-grep and **structurally unreachable** in
  CodeQL (`deserialize_seq` → `<<UNRESOLVED>>`); `vec!`-shaped allocation is precise in ast-grep and
  invisible in CodeQL (`vec!` expands 0/285). `docs/finding-class-map.md` currently carries R/E/N at
  the *class* level, which is now demonstrably the wrong granularity. Cheap — the measurements already
  exist (`docs/sast-layer.md` §10.1); this is a re-tabulation, not a new run. **Done-when:** the class
  map's grade column is keyed by (class, engine) and each cell names the measurement behind it.
- **W35 — run the FULL `codeql/rust-queries` built-in pack, and add Miri as an oracle**
  `[guide §5.1, §7][cheap]` — **DONE 2026-07-29, both halves** (`docs/sast-layer.md` §10.2, §10.3).
  *Result of the built-in half: a decisive zero.* All 18 security queries over 7 crates / 560 files,
  extraction gate passed on every DB first — **six of seven crates returned 0**, and lopdf's 109 are
  76 hard-coded passwords in `tests/`+`examples/` plus RC4/MD5 in its PDF standard-security-handler
  implementation, i.e. flagging the format. §3.1's finding now holds for the stronger engine too:
  for byte-parser targets the ground-truth-built rules are not a supplement to vendor defaults, they
  are the entire yield. *Result of the Miri half:* wired as a named oracle with a new template
  (`profiles/rust/harness-templates/panicking_drop.rs`), validated TP/TN on thin-vec
  RUSTSEC-2026-0103 — UB on 0.2.15, silent on 0.2.16 — which also verifies one of the guide's own
  ⚠-unverified advisory IDs. Original rationale below.
  We ran **one** built-in query (`rust/uncontrolled-allocation-size`), and
  it returned 0 for macro reasons that turned out to be structural. Never run:
  `rust/path-injection`, `rust/sql-injection`, `rust/access-invalid-pointer`,
  `rust/access-after-lifetime-ended`, `rust/regex-injection`, `rust/request-forgery`,
  `rust/cleartext-logging`, `rust/non-https-url`. Infrastructure is already standing — CLI in
  `~/codeql-home`, 5 databases in `~/cq-port` — so this is a prompt-and-read, not a build. Separately,
  **we use Miri nowhere.** For the soundness classes it is cheap and *definitive* on paths the test
  suite covers: not a candidate, a proof. Its highest-value specific form is the guide's
  **panicking-`Drop` harness** — a `T` whose `Drop` panics, driven through a container API under Miri —
  which converts an unwind-safety candidate into a confirmed defect. That composes with, not replaces,
  the existing find→fuzz gate. **Done-when:** every built-in Rust query has a recorded result (with
  `ExtractionCoverage.ql` run first, per L53, so a zero means something), and Miri is wired as a named
  oracle in the verify stage.
- **W36 — the soundness classes we have zero coverage of: S1 / S2 / S14** `[guide §4][gap]`. All 54 of
  our rules are DoS/resource/parse-shaped — recursion, loop, pop, alloc, limit, subtree, spawn,
  error-swallow. **Not one memory-safety or soundness class.** The gap the guide's taxonomy exposes:
  `unsafe impl Send`/`Sync` with bounds weaker than the field set requires (S1), a public *safe* fn
  that takes and dereferences a raw pointer, plus the high-precision companion — a raw-pointer owner
  implementing both `Drop` and `Clone` (S2), and `transmute` between two `repr(Rust)` types (S14).
  Previously blocked on "needs Dylint, and we pruned Dylint" — **no longer true**: we measured that
  CodeQL resolves types and impls (`runpaths.join` → `alloc/src/slice.rs` vs `p.join` →
  `std/src/path.rs`), and all three of these are type questions. Explicitly **out of scope**: S3
  (panic-safety across unwind edges) needs a MIR pass over unwind successors — the guide names it its
  own highest-cost item, and it is not reachable from either engine we run. Blocked-by W33: without
  paired fixtures there is nothing to falsify these against, and the `informational = "unsound"`
  advisories are exactly where their labelled data lives.
- **REJECTED, recorded so it is not re-proposed: the guide's CI-deployment framing.** Its `§1.2`
  `deployment_target` field and FP-budget table (5–20 % advisory / 1–5 % annotation / 0.1–1 %
  review-required / <0.1 % merge gate, "rule gets disabled org-wide after the third bad block") describe
  a CI product. **ADR-2 says the opposite by design:** SAST here is a candidate generator, never a
  verdict and never a gate; a false positive costs one agent read, a false negative costs the bug, and
  those are not symmetric. Adopting an FP budget would optimise the wrong one — the same mistake already
  made once and reverted in `rules/astgrep/rules/dvra-seeds.yml` (the name-based `validate_*`
  suppressor). Also rejected: its P0/P1/P2 wave schedule (we have `docs/sast-layer.md` §13 P0–P6, keyed
  to our own gates) and S13 (authorization bypass — needs a project-specific permission model our
  targets do not have).

**Where our measurements now exceed the source.** The guide's §6 (Rust analysis pitfalls) is written as
caution — *"assume it does not fire until shown otherwise"*. We showed it, with numbers: macro opacity
(`vec!` expands 0/285, 0/93, 0/15), monomorphisation (serde re-entrancy 0/6, `<<UNRESOLVED>>` at the
re-entry edge), and `cfg`/feature gaps (lopdf `reader.rs` 53/72, exactly its `#[cfg(feature = "async")]`
functions). Its §6 is a hypothesis list; ours is a measurement. Recorded in `docs/sast-layer.md` §10.1
and `LESSONS.md` L53.

- **W37 — the reachability judge does not gate on parser targets** `[E9][ADR-2]` — **RESOLVED
  2026-07-29 by REMOVING it.** Step 3 of the `sast-driven` skill is now `/triage`, which already does
  the four jobs the bespoke pass was reaching for (adversarial N-vote verify, dedupe, rank by derived
  exploitability, route) and is battle-tested and resumable. `normalize.py` emits `SAST-FINDINGS.json`
  — one candidate per cell, `severity: unknown`, every site listed. Original measurement below. First ground-truth scoring of the judge (29 blind agents, 4 crates with known fix
  sites): **recall 5/5, prune rate 7 %** — 27 `yes`, 2 `no`, 0 `unknown`. Both `no`s were refutations
  of the rule's CLASS, not of reachability. The question "can attacker input reach this class of site
  in this module" has a predetermined answer on a crate whose whole public surface eats untrusted
  bytes. **Where:** either move the judge behind a selectivity filter so it only ever sees few,
  rare-rule cells (E7c), or re-pose it per-SITE — "is this site on an untrusted path" — which is the
  question whose answer is not known in advance. **Done-when:** a judge pass on a parser target kills
  a materially larger fraction than 7 %, or the stage is explicitly repositioned as a cell-quality
  auditor rather than a gate.
- **W38 — exemplar selection hides the defect** `[E9]` — **RESOLVED 2026-07-29: the cap is gone, not
  tuned.** Cells carry every site, grouped by rule, rarest rule first. Re-measured on the same 8
  crates: defect site visible in **7 of 8**, up from **2 of 8**. The cap had no cost justification —
  median cell 10 hits, largest 337 ≈ 2.7k tokens, against a median 54k tokens each agent already spent
  reading source. Original measurement below. Measured: the pack found the real defect site in
  **7 of 8** E9 crates, but the site was among the 8 exemplars in only **2 of 8** — so the judge
  reasons about a sample that excludes the answer and has to rediscover sinks itself. **Where:**
  `docker/sast/normalize.py` cell assembly. Rank exemplars by the RARITY of the rule that produced
  them (E7c: hits/crate predicts discrimination), not by encounter order. **Done-when:** the fix site
  appears among the exemplars in a majority of a re-run E9 set.
- **W39 — split serialize-side from parse-side in the module key** `[E9]`. Six of 29 judges had to
  report that a cell's exemplars were write-path (`ser.rs`, `Registry::serialize`, `Dumper`) while the
  reachable members were parse-path. The module key is a directory, so `ser.rs` and `deser.rs` merge.
  **Where:** the `module_of()` key in `normalize.py` — add a direction facet (parse / serialize /
  mixed) derived from file name and enclosing item, so a judge is never handed both halves as one
  question. **Done-when:** no E9-style judge NOTE has to disambiguate direction.

**Landed straight out of E9, not backlog:** `ruleclass.py` no longer maps `unwrap_or*` to
`panic-surface` (it is total and cannot panic — five judges corrected it, two returned `no` on that
basis alone), and `normalize.py` now drops hits inside in-file `#[cfg(test)] mod tests` blocks
(path filters were blind to them; removes 17.2 % of hits on hickory-proto, cells unchanged).
- **W40 — rule for split-into-nested-container amplification** `[E10][false negative]`. Found by a
  `/triage` verifier, not by the pack: `kamadak-exif parse_ascii` (value.rs:432-433) does
  `split(|&b| b == b'\0').map(|x| x.to_vec()).collect::<Vec<Vec<u8>>>()` — **one heap allocation per
  NUL byte**, ~24× amplification on all-NUL input. The site IS in the U1 worklist (`rip-e004` fired at
  432), so enumeration covered it; no rule expresses the mechanism. **Where:** a new `cls-alloc` rule
  keyed on `collect()` into a nested container from an iterator produced by `split`/`chunks` over
  parsed data. **Done-when:** it fires on value.rs:433 and stays silent on the single-level
  `collect::<Vec<u8>>` shape.
- **W41 — no aggregate cap across sibling parsed entries** `[E10][mechanism, new class]`. Also from a
  verifier: kamadak-exif bounds each IFD entry's allocation against the input length
  (`tiff.rs:216-226`) but nothing bounds the **sum** across siblings, and value regions may fully
  overlap (`ofs = 0` for every entry passes the guard). 65535 entries × N bytes each ≈ **N²/12
  resident** (~68 GB from a 1 MB TIFF), all live because values are memoized in `MutOnce<Field>`. This
  is the **limit-bypass family's aggregate sibling** — the corpus's most common class (`RIP-E010`)
  covers "a cap exists, some path skips it"; this is "a per-item cap exists and is correct, and there
  is no total". **Where:** an enumerator pairing (per-item guard, loop over a parsed count) and asking
  whether a running total exists. **Done-when:** it opens a cell on the kamadak-exif shape and on
  `miniz_oxide init_tree`, which is the same question one level down.

- **W42 — read the target's SECURITY.md scope before forming cells** `[E12][scope]`. rustls declares
  `rustls-util` out of security scope in its own SECURITY.md; two cells (including the run's
  highest-prior one) sat there and an agent was spent proving it. The same file also declares what IS
  in scope (both provider crates) and names specific threat classes — which is exactly the class prior
  the skill says to rank by. **Where:** a recon step that parses `SECURITY.md`/`SECURITY.txt` for
  in/out-of-scope paths and threat vocabulary, attaching both to each cell. **Done-when:** a cell in a
  declared out-of-scope path is labelled as such before any agent sees it, and the target's named
  threats appear in the cell's class prior. Composes with the image-rs lesson (L34-family): the
  out-of-scope declaration is the single cheapest thing to read and the one most often skipped.
- **W43 — `publish = false` is now the workspace filter; extend the same idea** `[E12]` — **the filter
  itself LANDED** (`normalize.py`, 26 → 13 cells on rustls). Remaining: the same question one level
  out — a published crate can still ship modules behind non-default features that no default build
  compiles. **Where:** record each cell's feature gating from `#[cfg(feature = ...)]` at the file/module
  level and surface it, rather than silently mixing default-on and opt-in code in one cell.

## Backlog refresh (2026-07-29) — findings-ledger + lens-effectiveness measurement

- **W44 — auto-append `findings-ledger.jsonl` from the pipeline, don't hand-write it** `[ledger][measurement]`.
  The lens-attribution ledger (`findings-ledger.jsonl` + `scripts/lens_stats.py` + `findings-ledger.README.md`)
  is the instrument that makes the 4-lens design measurable — per-lens surfaced/live/precision, the
  U1-vs-U2 `sast_enumerated` signal, independent-corroboration overlap. Right now it is hand-assembled
  after a campaign, which is exactly how the rust-in-peace credit line got dropped once (W5) — a prose
  rule outside the templated path fails. **Where:** the `/triage` skill's Phase 6 output and the
  `sast-driven` finder should each emit a ledger row per finding by construction (`found_by` from the
  lens that spawned the agent, `first_by`/`sast_enumerated` from the run, `verdict` from triage,
  `model` from the agent's model). A finding that reaches a verdict without a ledger row is the failure
  to catch — mirror L52's "assert on the artifact." **Done-when:** a campaign's findings appear in the
  ledger without a manual edit, and `scripts/lens_stats.py` is run at campaign close as a standing step.
  **Caveat to encode (from the ledger README):** per-lens credit is only clean when a lens runs as its
  OWN agent — folded blind+TM+CVE agents must record all three in `found_by` with a single `first_by`,
  or the precision numbers lie. The auto-append must know whether the run was folded or separate.
- **W44 — rule: length subtraction with no dominating floor guard** `[embargoed finding][rule-dev-eligible]`.
  An embargoed finding (advisory deferred) is a clean rule seed: `X.len() - CONST` (or `- field`) used as
  a split/index/capacity, NOT preceded on every path by a `if X.len() < CONST { return … }` floor. The
  ground truth is a **control asymmetry across implementations**: one implementation has the bare
  subtraction, a sibling has none, and the crate's own guarded call sites show the floor-checked form.
  That is exactly the shape variant-analysis wants — a rule keyed on "len-subtraction whose
  operand is not floor-checked in the enclosing fn", with the guarded siblings as negatives.
  **Done-when:** it fires on the unguarded site and stays silent on the guarded siblings. Note the
  honest limit: this is the pattern-engine dominance weakness — a pattern engine can only approximate
  "on every path"; CodeQL's CFG is the precise home (E4 routed guard-dominance to CodeQL). Seed both,
  measure, keep whichever discriminates.

## Backlog refresh (2026-07-30) — SAST rules as scope-narrowers; funnel-attribution enforced

- **W45 — build SAST rules to NARROW SCOPE (sink-enumerators), score on enumeration not precision**
  `[E13][L54/L55][rule-dev]`. The measured result is unambiguous: SAST **rule** precision is
  **7/305 = 2.3%** (E13) and 0/34 recorded on Chrome; all 24 e13 ledger findings were **found-alongside**
  (a reasoning agent triaging a wrong cell), 0 were rule-hits. Root cause is structural, not a bad rule:
  verification traces **bottom-up from the sink to the trust boundary**, and a pattern rule has no call
  graph/dataflow, so it cannot decide reachability — posing as an oracle caps it near chance (L55). The
  actionable pivot: design each rule as a **precise sink-enumerator** — flag one well-defined dangerous
  shape (`vec![0; parsed_len]` / recursive parse fn with no depth param / unchecked slice-index sized by
  a parsed field / `X.len() - CONST` without a dominating floor, cf. W44) **and little else**, so its
  hit set is small enough that a reader can trace *every* member up. **Metric change (blocks W28's
  scoring):** stop scoring rules on precision-at-the-bug; score on **enumeration** = sink-recall (does
  the flagged set CONTAIN the real sink sites?) × set-tightness (hits/kLOC — a pack at L54's median 396
  hits/crate has narrowed nothing). A rule earns its place by being *selective*, not by "finding bugs".
  **Done-when:** a rule set whose union covers the known sink sites of a target class at a stated,
  small FP multiple, with per-rule hits/kLOC reported; `docker/sast/prune_report.py` prunes on the
  enumeration metric, not on a TP/FP that conflates rule-hit with found-alongside.
- **W46 — separate the two SAST verdict channels in every artifact** `[E13][L55][measurement]`. The
  `sast_enumerated` field is the load-bearing distinction (`site-hit`/`adjacent` = the rule found the
  site; `site-missed`/`misdiagnosed` = found-alongside). Enforce it end-to-end: the `sast-driven` skill
  must set `sast_enumerated` per finding from the cell→finding provenance (not default it to a flattering
  `direct-hit` — that mislabel was corrected across 24 rows on 2026-07-30), and `lens_stats.py` (done)
  reads it. **Done-when:** no ledger row carries an unverified `direct-hit`; the SAST section of
  `lens_stats.py` is driven by real provenance, and `docs/mechanism-effectiveness.md`'s numbers
  regenerate from the ledger + `E13-result.json` without hand-editing.
- **W47 — evaluate a "prior-art cross-check" gate before disclosure — is it worth building?** `[L57][L58][disclosure]`.
  Motivation: find011 (`http` `PathAndQuery` u16 truncation) was a genuine SAST finding, PoC-confirmed,
  but already **fixed** (`http` 1.5.0) and **publicly reported** (hyperium/http#855) before our run — the
  manual gate caught it, but only after a full PoC spend. The question is whether to AUTOMATE the check,
  not whether to do it (L57/L58 already mandate doing it manually). Two rungs to price: (a) cheap — a
  `disclose`-stage checklist/prompt that refuses to emit an artifact until the analyst records the
  latest-release PoC result **and** an issue-tracker + CVE/RustSec/GHSA/OSV search for crate+symbol;
  (b) expensive — automated queries (crates.io latest version, GitHub issue/PR search, RustSec
  advisory-db, OSV) keyed on crate+symbol, run in the pipeline. **Done-when:** a one-page measurement —
  replay the existing findings/ledger corpus and count how many findings the cross-check would have
  reclassified as fixed-upstream or already-reported (the base rate of rediscovery) — plus a recorded
  go/no-go: build (b) only if that rate is high enough to pay for the query plumbing; otherwise ship (a).
- **W48 — deploy-layer preflight: shipped for the SAST mode; generalize to every container mode.** `[SHIPPED][L59][deploy]`.
  `scripts/preflight-deploy.sh` (image-present · export-canary · egress-canary · result-writeback) now
  gates `docker/sast/sast-scan.sh`, settling in seconds the daemon traps that otherwise surface an hour
  into a build at layer export. Proven on a hardened box (`userns-remap` + `containerd-snapshotter` +
  `iptables: false`) where the image build failed three separate ways, each at its own expensive moment
  (L59). **Remaining:** call the same preflight from every other container-using entry point
  (vuln-pipeline build/grade, patch verify), and add a `--dry-run` that prints the environment verdict
  alone. **Done-when:** every mode that runs a container refuses to start until the preflight passes,
  and the SAST bring-up doc (`docs/case-studies/sast-driven-bringup.md`) points at it as step 0.
