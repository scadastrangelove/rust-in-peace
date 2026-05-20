# Triage: "How do I go through these hundreds of findings?"

Your pipeline (or another scanner) just produced a pile of raw findings.
The `/triage` skill turns that pile into a short, ranked, owned list that
engineering can act on.

## What it does

Four jobs, in one pass:

1. **Verify.** Adversarially checks each finding against the source code
   (read-only, no execution). Drops the ones that aren't real.
2. **Deduplicate.** Collapses the same root cause reported N times across
   parallel runs or multiple scanners.
3. **Re-rank.** Derives severity from preconditions and your stated trust
   boundary, not from whatever the scanner claimed. A "HIGH" behind one or
   two preconditions and authenticated access becomes a MEDIUM; three or
   more becomes a LOW.
4. **Route.** Tags each survivor with a component owner so it lands on the
   right desk.

Output: `TRIAGE.md` (human-readable, ranked) + `TRIAGE.json`
(machine-readable, for your tracker).

## Dedup: by root cause, not symptom

You can't hash LLM output to deduplicate it; the phrasing always changes.
The rule that works: **two findings are duplicates if fixing one fixes the
other.** Apply it in two passes: a cheap deterministic pass first (same
file, same category, line numbers within ten), then an LLM pass for what
remains, using these semantic rules:

- **Duplicate:** same root cause worded differently; a shared vulnerable
  helper reported at every call site; a missing global protection (like an
  auth check) reported per-endpoint; a cause and its consequence flagged in
  the same path.
- **Distinct:** different bug types in the same file block; different
  variables reaching different sinks; two independent bugs inside one
  helper; two endpoints missing a check where each requires its own fix.

## Severity: rate by preconditions

Labeling every SQL injection "high" teaches engineers to ignore your alerts.
Base severity on what an attacker actually has to do:

- **Reachability.** Can a real entry point reach the code, or is it a test
  artifact? Reachability is your sharpest filter: excluding anything
  unreachable from a real entry point drastically shrinks the queue, and a
  working PoC is the strongest reachability signal you can get.
- **Attacker control.** Does untrusted input actually reach the sink, or is
  it sanitized upstream?
- **Preconditions.** What state must exist first: a specific flag, prior
  auth, a race window?
- **Authentication.** The jump from pre-auth to post-auth or admin-only is
  usually your largest severity multiplier.
- **Read vs. write.** Writes escalate; reads leak but don't corrupt.
- **Blast radius.** One user vs. all users, one tenant vs. the platform,
  userland vs. kernel.

Force the model to list preconditions *before* mapping the count to a score.
Zero preconditions with unauthenticated remote access: high. One or two, or
an authenticated path: medium. Three or more, or local-only: low. Tune
thresholds to your system.

Verification and triage are independent. Verification says "this is real";
triage says "this is worth your next sprint." A confirmed Low is still a
Low; don't let verified status inflate priority, and keep a human on
everything rated high or above.

## Run it

```bash
# On pipeline output:
> /triage results/<target>/<timestamp>/ --repo ./path/to/source

# On skill output:
> /triage ./VULN-FINDINGS.json --repo ./path/to/source

# Non-interactive, higher confidence (5 verifier votes per finding):
> /triage ./findings/ --auto --votes 5 --repo ./path/to/source
```

By default it **interviews you first**: trust boundary, threat model,
scoring standard (HIGH/MED/LOW vs. CVSS vs. your org bug-bar), and whether
to bias toward precision or recall on split votes. These answers shape
verification and ranking. Pass `--auto` to skip the interview and use
precision-biased defaults.

## When to reach for it vs. fixing the pipeline

- **You have a noisy batch right now:** run `/triage`. It's the operational
  fix and cleans up what's on disk today.
- **Every batch is noisy:** fix it at the source. See
  [best-practices.md #11](best-practices.md#judge)
  (add a skeptical judge agent) and
  [troubleshooting.md: Duplicate findings](troubleshooting.md#duplicate-findings)
  (seed `known_bugs` so agents don't re-converge).

The pipeline's own grade/judge/dedup stages already do some of this inline;
`/triage` is the cross-run, cross-scanner layer on top, and it works on
*any* findings file, not just pipeline output.

## After triage: patch

Work the top of `TRIAGE.md`. For pipeline-produced crashes (PoC + ASAN
trace), `vuln-pipeline patch` generates and verifies a fix per crash with a
build → reproduce → regress → re-attack ladder; see
[patching.md](patching.md). For findings without a runnable PoC, see
[patching.md's static mode](patching.md#campaign-style-patching-the-patch-skill-static-mode).

Skill source: `.claude/skills/triage/SKILL.md`
