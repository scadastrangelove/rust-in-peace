# Patching: closing the loop

The pipeline's `patch` stage takes a verified crash from a `vuln-pipeline run`
results directory and produces a fix that passes an executable verification
ladder. The same two-container trust boundary as find↔grade applies: the
patch agent works in one container, a fresh grader container verifies the
diff, and only the diff bytes cross.

This is the natural step after [triage](triage.md): you have a queue of
verified, ranked crashes; this turns each one into a candidate fix you can
review and upstream.

> **Two front doors, one output shape.** The `/patch` skill accepts
> `TRIAGE.json`, `VULN-FINDINGS.json`, or a pipeline results directory and
> writes `PATCHES/bug_NN/{patch.diff, patch_result.json}`. On pipeline input
> it delegates to the `vuln-pipeline patch` CLI documented below; on static
> findings (no PoC) it runs the [campaign-style
> flow](#campaign-style-patching-the-patch-skill-static-mode). The
> `verified` field in `patch_result.json` tells you which path produced the
> diff: `ladder_passed` / `ladder_failed` (executable oracle) vs
> `static_review_only` (agent review). The rest of this document covers the
> execution-verified ladder; everything in
> [§Reviewing generated patches](#reviewing-generated-patches) applies to
> both.

> ⚠️ **The patch grader executes target code and applies model-generated
> diffs to it.** Same isolation requirements as the find stage apply; see
> [security.md](security.md). And see [§Reviewing generated patches](#reviewing-generated-patches)
> below before upstreaming anything; the verification ladder proves the
> crash is fixed, not that the diff is free of new problems.

## Install and first run

The patch stage ships with the pipeline; no extra install. Your target's
`config.yaml` needs a `build_command` (the in-container rebuild step after
applying a diff) and optionally a `test_command` (the regression suite for
the regress tier). The four shipped targets already have these.

```bash
# After a find run has produced results/<target>/<ts>/:
vuln-pipeline patch results/<target>/<ts>/ --model <model>

# Or try it standalone on the pre-baked canary fixture (no find run needed):
vuln-pipeline patch targets/canary/fixtures/results_sample --model <model>

# One bug, more iterations, skip re-attack for speed while iterating on prompts:
vuln-pipeline patch results/<target>/<ts>/ --bug 0 --max-iterations 8 --no-reattack
```

Output lands in `<results_dir>/reports/bug_NN/{patch.diff, patch_result.json}`
alongside the existing exploitability report. Transcripts stream to
`patch_transcript_itN.jsonl` and `reattack_transcript_itN.jsonl` per
iteration.

## Architecture

**Dedup and order.** The CLI walks `result.json` files under the results dir,
groups by crash signature, and orders them the same way `report` does, so
`bug_NN` here is the same `bug_NN` the report stage wrote.

**Patch agent** (container A, in the agent sandbox: gVisor + `vp-internal`
egress-only network, see [agent-sandbox.md](agent-sandbox.md)). Gets the
source tree, the PoC at `/tmp/poc.bin`, the reproduction command, and the
ASAN trace. The agent's prompt (`harness/prompts/patch_prompt.py`) walks
seven steps: reproduce the crash; trace backward from the crash site to the
root cause and fix there; grep for sibling call sites with the same pattern
(variant hunt); produce the smallest diff that fixes the root cause; an
adversarial self-check ("name one input variation that reaches the same bad
state without tripping your check; if you can, your fix is at the wrong
layer"); rebuild and re-run the PoC; emit a `git diff` from a baseline
commit. The agent also emits `<variants_checked>` and `<bypass_considered>`
tags so you can see what it considered.

**Grade** (container B, same sandbox, fresh from the same image). Only the
diff bytes cross from A to B. Walks the verification ladder, short-circuiting
on the first failing tier. Re-attack snapshots container B as a temporary
image (`docker commit`) and runs a fresh find-agent against that.

**Iterate.** A failing verdict's evidence (compiler error, ASAN trace, test
output, or the re-attack crash) is fed back into the next patch-agent
iteration's prompt. Up to `--max-iterations` (default 5). Each iteration
overwrites `patch.diff` / `patch_result.json` so the last attempt is what's on
disk.

## The verification ladder

Every gating tier is an **executable oracle**: compiler, sanitizer, or test
runner. No tier that decides pass/fail is an LLM judgment.

| Tier | Question | Oracle | Field in `patch_result.json` |
|---|---|---|---|
| **Build** | Does the patched tree compile? | `git apply` + `build_command` exit code | `t0_builds` |
| **Reproduce** | Is the original crash gone? | Exit 0 AND no `AddressSanitizer:` in output | `t1_poc_stops` |
| **Regress** | Did it break existing behavior? | `test_command` exit code (skipped if none) | `t2_tests_pass` |
| **Re-attack** | Root cause gone, or just this input? | A fresh 50-turn find-agent attacks the patched binary; ASAN decides | `re_attack_clean` |
| Style | Would a maintainer accept it? | LLM judge 0-10; **advisory only, never gates** | `t3_style_score` |

A patch passes when build, reproduce, regress (or no suite), and re-attack are
all clean.

**Why re-attack matters.** A patch that compiles and stops the specific PoC is
the easy part: published evaluations of model-generated security patches
show roughly 60% clearing build-and-reproduce checks, but under 15% surviving
fuzzing and differential testing. The dominant failure mode is a bounds check
at the crash site (the `memcpy` ASAN flagged) that leaves the bad value
reachable from a slightly different input. Re-attack is the mechanical guard
against that: a fresh find-agent gets 50 turns against the *patched* binary,
scoped to the original crash's code path. Any crash it lands fails the
verdict; the agent generates the attack, ASAN decides whether it succeeded.

**Sensitivity caveat.** Treat a re-attack pass as "no bypass found in 50
turns," not "root cause proven fixed." It discriminates well when a bypass
input is constructible inside the turn budget; it can miss wrong-layer fixes
whose bypass requires hard-to-construct preconditions. On failure the
iteration loop feeds the bypass crash back to the patch agent, which
typically widens the fix.

## Reviewing generated patches

The verification ladder proves the crash is fixed. It does **not** prove the
diff introduces no new problems. Build, reproduce, and regress are
correctness checks against the *original* behavior; re-attack hunts for
variants of the *original* bug. None of them is a semantic review of the diff
for new vulnerabilities, logic changes outside the fix, or anything a
maintainer would reject on sight.

Treat `patch.diff` as a strong draft that needs a human read before it goes
anywhere. Things to look for:

- **Scope creep:** changes to files or functions unrelated to the crash path.
- **Suppression instead of fix:** `try/except: pass`, early-return on the
  exact PoC value, disabling the assertion that fired.
- **New attack surface:** added parsing, new size fields trusted from input,
  weakened validation elsewhere to make the fix "work."
- **Correct diagnosis, wrong fix.** The model often identifies exactly which
  module needs to change but proposes a narrow patch that breaks something
  else (e.g. fixes the type at the call site instead of the callee, or
  hardcodes the PoC's value). Expect to sometimes keep the analysis but
  rewrite the diff.

Two things worth doing with a fresh agent before upstreaming, because
neither the patch agent's in-loop self-check nor the ladder gives you them:

- **Re-run the adversarial self-check out of context.** The patch agent
  already asks itself *"name one input variation that reaches the same bad
  state without tripping your check"* (step 5 of its prompt), but it's
  grading a diff it just wrote, with its own reasoning in context, a
  classic anchoring problem. Run the same question against the final
  `patch.diff` in a fresh context. If the fresh agent names a bypass the
  original missed, the fix is at the wrong layer.
- **Simplify in a fresh context.** The agent is prompted for a minimal
  diff, but its idea of minimal is anchored to the change it just reasoned
  through. Generated patches often still carry refactors, drive-by
  cleanups, or reformatting, which make them harder to review and more
  likely to introduce new bugs. A fresh-context pass asked only for "the
  smallest change that fixes the root cause" reliably trims them.

If the diff is sound but you can't apply it directly (different repo, style
conventions the model doesn't know, an editing-restricted environment), a
pattern that works well is to have the model emit a precise *prompt*
describing the logical change (what the control flow should be, which
invariant to enforce, where) and hand that to whatever agent or developer
owns the codebase. The find-side model has the security context; the
apply-side has the project context. A human reviews the logical change in
between.

For complex fixes, give the patch agent an explicit bailout: if the change
touches more than N files, or the agent's own confidence is low, escalate to
a human with the analysis instead of emitting a diff.

The optional `--style` flag runs the advisory style judge and writes a 0-10
score into `patch_result.json`. It's a hint, not a clearance.

The patch agent's prompt reads target-derived data (the ASAN trace, the
exploitability report, and on retry the build/test output). The pipeline fences
those with per-call random delimiters and instructs the agent to treat them
as data, not instructions. But prompt-level fencing is a mitigation, not a
guarantee. If you're running against third-party code you don't fully trust,
the diff review is where a poisoned target's influence would surface. See
[security.md](security.md#prompt-injection) for the broader threat model.

## CLI reference

```bash
vuln-pipeline patch <results_dir> --model <m>           # all unique bugs
vuln-pipeline patch <results_dir> --bug N               # only bug_NN
vuln-pipeline patch <results_dir> --parallel            # run patch agents concurrently
vuln-pipeline patch <results_dir> --no-reattack         # build/reproduce/regress only (faster, weaker)
vuln-pipeline patch <results_dir> --style               # also run advisory style judge
vuln-pipeline patch <results_dir> --max-iterations N    # fix↔grade cap (default 5)
vuln-pipeline patch <results_dir> --max-turns N         # per-iteration agent budget (default 200)
vuln-pipeline patch <results_dir> --engagement-context <file>   # org-specific auth block
```

## Harness-driven re-attack

For targets that can't be driven as `./binary < input` (anything that needs
a launcher, environment setup, multi-process orchestration, or a non-file
input channel), set `reattack_harness: <path>` in the target's
`config.yaml`. The re-attack find-agent then writes PoCs to `/poc/` and runs
that script instead of invoking the binary directly. The output contract
(`<poc_path>`, `<reproduction_command>`, `<crash_output>`, `<dup_check>`) is
identical to the default mode, so the grader and dedup are unchanged.
Leaving `reattack_harness` unset keeps the default `./binary < input`
behavior.

The image must provide the harness script with this exit-code contract:
runs every file under `/poc/` against the instrumented target (fresh state
per PoC; sanitizer output captured), exits 1 with the trace on first crash,
0 if all pass, 2 on launch failure. Any target-specific driver goes inside
that script; the find-agent only depends on the exit codes.

## Customizing for your codebase

This implementation is the C/C++ memory-safety shape: ASAN as the reproduce
oracle, `git diff -- '*.c' '*.h'` as the patch format. For other languages and
vulnerability classes the *ladder* generalizes (apply, rebuild, reproduce,
regress, re-attack) but the per-tier oracles change. The
[`/customize`](customizing.md) skill walks through porting; the short version
is `harness/patch_grade.py:_t1_passes()` (what counts as "the bug is gone")
and `harness/prompts/patch_prompt.py` (how to ask for the fix) are the two
files that encode the domain.

## Campaign-style patching: the `/patch` skill static mode

The `vuln-pipeline patch` flow assumes the pipeline's own crash artifacts as
input: a PoC file, an ASAN trace, a reproduction command. If your findings
come from elsewhere (a separate scanner, manual review, a prose-only report
without a runnable PoC), or you're patching a class of bugs across many call
sites rather than one crash at a time, that input contract doesn't fit.

The `/patch` skill's static mode handles this case directly:

```bash
> /patch ./TRIAGE.json --repo ./my-service --top 5
# → PATCHES/bug_NN/{patch.diff, patch_result.json}, PATCHES.md
```

For each finding it spawns a fresh-context patch agent (root-cause-first,
variant hunt, minimal diff, regression test emitted as part of the diff) and
a separate reviewer agent that sees only `{file, line, category}` plus the
diff bytes (never the scanner's prose) and judges scope, suppression, and
new attack surface. The skill never applies a diff; output is inert text in
`./PATCHES/` for human review. Every result is labeled
`verified: "static_review_only"` so it cannot be confused with a
ladder-passed fix.

With no PoC, there is no reproduce tier, so the regression test the patch
agent emits is the only executable oracle you have. **Write the test before
the patch**: have the agent emit a test that reproduces the bug, confirm it
fails, write the fix, confirm it passes. A patch without a failing-then-
passing test is unverifiable; it can silently regress and you can't prove
the bug was ever real. Don't merge a static-mode patch whose test doesn't
fail on the unpatched tree.

The fuller reference architecture this is drawn from, for migrations large
enough to need worktrees and per-ticket PRs:

1. **Research.** An agent reads the finding plus the codebase and produces a
   migration plan: which sink pattern is unsafe, what the safe replacement
   API is, where the call sites are.
2. **Spec as tests.** Encode the plan as a failing test suite (one test per
   call site) that passes when the migration is done. This is the executable
   oracle that replaces ASAN.
3. **Tickets.** Split the test suite into independently mergeable units of
   work, each small enough to review.
4. **Patch in parallel.** One worker subagent per ticket, in its own git
   worktree, looping fix↔verify against its slice of the test suite plus the
   project's existing tests.
5. **Gate.** Each worker's diff passes a four-prong gate before it opens a
   PR: the oracle tests, an independent bug sweep, a no-tools code reviewer,
   and any project-specific extra checks. Human review at the PR.

The trust-boundary principle is the same: the verifier runs in fresh
context the patch author never touched. The oracle changes from "ASAN says
clean" to "the test suite I wrote before touching the code now passes." The
`/patch` skill ships steps 1, 4, and a read-only variant of 5; for the full
worktree-per-ticket orchestration see the [other use
cases](other-use-cases.md#vulnerability-patching) discussion.

---

See [pipeline.md](pipeline.md) for the find/grade/report stages this builds on,
[customizing.md](customizing.md) to port the ladder to another domain, and
[best-practices.md](best-practices.md) for the iterate-until-clean loop after
patching.
