# Troubleshooting / common pitfalls

## Duplicate findings

Independent agents converge on "lowest hanging fruit." The pipeline mitigates
this with a shared `found_bugs.jsonl` that agents populate during discovery
and deduplicate against before submitting, but this doesn't eliminate all
collisions. A second run, feeding the first run's findings into
`config.yaml`'s `known_bugs`, helps agents avoid re-converging on the same
paths.

For interactive scanning, run `/triage ./VULN-FINDINGS.json` to collapse
duplicates and re-rank by derived exploitability.

## Rate limits

As a rough guideline, expect ~10K uncached input tokens/min and ~2K output
tokens/min per agent. You can scale parallelism up to your account's ITPM
limit (roughly **10 agents per 100K ITPM**). You can check your limit in
the [Claude Console](https://console.claude.com/settings/limits).

Bursting past your limit is not catastrophic. The pipeline resumes on 429
without losing conversation context (see 
[pipeline.md#resume-on-error](pipeline.md#resume-on-error)).
You should not need to throttle far below provisioned capacity.

## Skill run died mid-way on a large codebase

`/threat-model bootstrap` and `/triage` write per-stage checkpoints to
`./.threat-model-state/` and `./.triage-state/` respectively, next to their
output. If a run dies from context exhaustion, rate limits, or Ctrl-C, **just
re-invoke the same command**. It reads `progress.json`, restores state from
the per-stage JSON files, and picks up at the next stage/phase without
re-spawning the subagents that already finished. Pass `--fresh` to discard the
checkpoint and start over.

Checkpoints are written atomically (via `.claude/skills/_lib/checkpoint.py`),
and the final output (`THREAT_MODEL.md` / `TRIAGE.md`) is appended one section 
at a time. So, a stall mid-output just loses one section, not the whole file.

## Pipeline run died mid-batch

```bash
bin/vp-sandboxed run <target> --runs N --resume results/<target>/<ts>/
bin/vp-sandboxed report results/<target>/<ts>/          # skips already-reported bugs
bin/vp-sandboxed report results/<target>/<ts>/ --fresh  # force full re-report
```

`--resume` skips any run whose `result.json` reached a terminal status
(`crash_found` / `crash_rejected` / `no_crash_found`) and retries the ones
that failed (`agent_failed`/ `build_failed`/`error`). `found_bugs.jsonl` and 
`focus_areas.json` carry over, so resumed runs see the same dedup context.

This pipeline-level resume, which survives a killed orchestrator, is different
from the per-agent session resume described in 
[pipeline.md#resume-on-error](pipeline.md#resume-on-error), which restores a 
single agent's conversation after an API error.

## False positives

The most common cause of false positives isn't the model misreading code, it's 
the model not knowing your trust boundaries. If a whole class of findings is
wrong in the same way, write the missing assumption into your `THREAT_MODEL.md`.
The blog post's [threat-model section](https://claude.com/blog/using-llms-to-secure-source-code)
describes this in detail and explains why this is the place to start.

Two other fixes may also help:
- **Add a skeptical judge.** A separate agent that reads each finding and
  critique of it, then decides. Models reliably downgrade their own findings
  when asked directly.
- **Look for the mitigation the model couldn't see.** A frequent
  false-positive shape is that the code path is real, but validation in a calling
  service or a shared sanitizer makes it unreachable. Ask the model what
  upstream context it wants (calling services, configs, middleware) and
  provide it, or feed traces/logs that show the mitigation firing at
  runtime.

Tune precision before recall - get the false-positive rate down to where you
trust the output, *then* widen the net. Fixing precision first also makes any
later recall gains legible, since you can trust that new findings are real.

## Coverage and diminishing returns

If the first scan only touched a small fraction of the app surface, the fix is
usually recon, not more find agents. Raise the focus-area count or feed recon an endpoint
inventory so it partitions the full surface. Adding find agents without 
re-partitioning hits diminishing returns fast, as they are likely to converge
on the same bugs.

One completeness signal worth tracking is lines of code touched across all
find transcripts. Use any missing code paths as focus areas for future find
agent runs.

## Subagents using the wrong model

Claude Code may launch subagents on a lower-tier model than your main
session. Pin them:

```bash
export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>
```

Or set `model: inherit` in your subagent definitions. If anything requests a
model by tier name, you can also pin what each tier resolves to using
`ANTHROPIC_DEFAULT_HAIKU_MODEL`, `ANTHROPIC_DEFAULT_SONNET_MODEL`, and
`ANTHROPIC_DEFAULT_OPUS_MODEL`.

## Re-attack didn't reproduce the finding (rust)

`vuln-pipeline reattack` turning up nothing is often a *fit* result, not a
failure. The find→fuzz bridge only reproduces a finding when a fuzz template
fits the finding's shape and the profile's detector (Miri/panic/hang) can
observe the bad state under fuzzing. A soundness or logic finding with no
detector-visible crash, or one whose shape no shipped template covers, will
come back clean without meaning the finding was wrong. Read the reattack
transcript to see which template ran, and check the finding's capability route
(below) before concluding the bug isn't real. Route it through
[triage](triage.md) rather than discarding it.

## `capabilities.json` missing or misparsed (rust)

Capability routing (`harness/capabilities.py`) reads a target's
`capabilities.json` to decide which fuzz templates the find→fuzz bridge applies.
If that file is absent, empty, or has capability keys that don't match the ones
in [`profiles/rust/capabilities.md`](../profiles/rust/capabilities.md), the
router has nothing to route on and reattack falls back to little or no fuzzing —
so findings that a fitted template would have reproduced come back clean. Check
that `capabilities.json` exists next to the target's `config.yaml` and that its
keys are spelled exactly as the capability table lists them.

## Scorecard reports 0 bugs

A `vuln-pipeline scorecard` of zero is a claim that needs a reason, not a green
light. The scorecard exists to force that reason to be explicit: either the
target really is clean (say why — small surface, prior audit, no untrusted input
reaches the unsafe code), or the run under-covered the surface. Before trusting a
zero, confirm find agents actually reached the risky code (lines-of-code touched,
per the coverage section above) and that capability routing engaged, rather than
assuming the target is clean.

## Miri / nightly build timeouts (rust)

The rust detector runs Miri and nightly-toolchain builds, which are far slower
than a plain ASan compile — a Miri pass over a non-trivial target can dominate a
run's wall-clock. If find or grade runs are timing out on the build or detector
step rather than on agent turns, raise the per-agent budget (`--max-turns`) and
the build timeout for rust targets, and expect a rust wave to take longer than an
equivalent cpp one.