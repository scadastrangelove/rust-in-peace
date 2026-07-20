# IMPROVEMENTS — backlog refilled from the real-OSS campaigns (x509-parser + lopdf)

The original P0/P1/P2 backlog is exhausted (all done + pushed). This refill is derived from what the
real-OSS campaigns exposed — see [`LESSONS.md`](LESSONS.md) (evidence now spans **L1–L37**; P0/P1.4
close L1–L14, the disclosure-lifecycle items P1.5–P1.7 close L15/L16/L23/L27/L29/L32/L33/L34, and the
still-open tail L35–L37 + basket-3 items are in the Backlog refresh at the end). Priority = ROI
(impact ÷ effort), not severity. Each item names **where** it lands and a **done-when** acceptance
check, so it can be picked up cold.

Tag key: `[Ln]` = lesson it closes · `[camp]` = campaign that surfaced it.

## Implementation status (2026-07-18) — generalized to any profile & landed

The P0 core + P1.4 shipped as **profile-agnostic** modules (keyed on the same
swappable nouns as `profiles.py`, not Rust-specific), each pure + unit-tested
(95 pure tests green, no cpp/rust regression). See `docs/extending.md` §
"Cross-cutting admissibility & profile-hygiene gates".

| Item | Status | Module / hook | Tests |
|------|--------|---------------|-------|
| P0.1 shipping-profile gate | **done** | `harness/build_profile.py` (registry keyed by profile: rust/cpp gated classes; android none) | `tests/test_build_profile.py` |
| P0.2 dep-citation gate | **done** | `harness/admissibility.py` (`VerdictClaim.dep_citation` → CONTESTED) | `tests/test_admissibility.py` |
| P0.3 soak = distinct sites | **done** | `harness/soak.py` + `scripts/run_fuzz_soak.sh` (dedup via profile detector) | `tests/test_soak.py` |
| P0.4 capability-gate crash track | **done** | `capabilities.CapabilityInventory.run_crash_track()` + `crash_track_skip_reason()` | `tests/test_capabilities.py` |
| P0.5 flag construction repros | **done** | `harness/admissibility.py` (`HARNESS_DIRECT_CONSTRUCTION` → UNVERIFIED) | `tests/test_admissibility.py` |
| P1.4 where_checked forcing fn | **done** | `harness/admissibility.py` (`VerdictClaim.where_checked` → CONTESTED) | `tests/test_admissibility.py` |
| P0.6 verdicts-not-counts | **partial** | `soak.format_site_report` leads with sites; report template still to lead with dispositions | — |
| P1.1/P1.2 always-run seeded fuzz + auto-escalate | **spec+hooks** | prompt/skill-shaped: profile `find*` prompt + reattack bridge (L11) | — |
| P1.3 adversarial maintainer-review | **spec+hooks** | judge-shaped pre-disclosure agent before `DISCLOSURES.md` (L13) | — |

The pure gates are wired to plug into `grade`/triage additively (backward-compat,
same staging as `witness.py`); the remaining items are prompt/skill work on stages
a profile already provides.

## Landing/wiring status (2026-07-20) — read this before trusting the "done" column above

A wiring audit (what actually runs automatically vs. what's only prose/branch) found two
gaps between the table above and `main`:

1. **The "done" P0/P1.4 modules are NOT on `main`.** `witness.py`, `admissibility.py`,
   `build_profile.py`, `soak.py`, and `predisclose.py` are coded + unit-tested but committed
   only on the `security/self-review-fixes` / `android-app-profile` / `apptrust-basket3`
   branches — they sit as uncommitted working-tree files, not on `main`, so from the shipped
   repo's perspective they don't exist yet. **Decision (2026-07-20): keep them on-branch for
   now; land as a deliberate batch later.** Tracked as **W1** below.
   What IS on `main`+remote: `aggregate.py`, `capabilities.py`, `reachability.py`, `corpus.py`,
   `feedback.py`, `find_to_fuzz.py`, `find-ceiling.md`, all 7 skills (commits `800134d`/`0a908de`).
2. **The three-pass find (blind ∪ TM-first ∪ CVE-seeded) had never been institutionalized** —
   it ran as a hand-invoked scratchpad workflow (`find_engine.mjs`) every campaign, prose-only
   in `LESSONS.md` L21/L25 + `docs/variant-analysis.md`. **DONE 2026-07-20: promoted to the
   `/variant-scan` skill** (`.claude/skills/variant-scan/` — SKILL.md + the `find_engine.mjs`
   reference orchestration, on `main`). Remaining (CLI stage / auto-invoke) tracked as **W2**.

### W1 — land the on-branch profile-hygiene modules to `main`  `[wiring]`
`witness.py` + `admissibility.py` + `build_profile.py` + `soak.py` + `predisclose.py`
(and the `apptrust`/`android-app` profiles that depend on `witness.py`) are done+tested but
only on branches. Held deliberately, not forgotten.
- **Where:** merge/cherry-pick the reviewed subset onto `main`; re-run the pure suite on `main`.
- **Done-when:** `git cat-file -e main:harness/{witness,admissibility,build_profile,soak,predisclose}.py`
  all succeed; the "done" rows above stop being aspirational. Decide per-module (some, like
  `witness.py`, are load-bearing for two profiles; others can wait).

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
  the Tamm box + agent auth) hasn't proven the profile drives the escape oracle and recalls the
  seeded bugs while sparing the decoy. Do before treating `apptrust` as production-ready.
