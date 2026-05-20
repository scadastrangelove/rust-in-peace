# Troubleshooting / common pitfalls

The most common practical pitfalls when running or building a pipeline:

1. Duplicate findings
2. Rate limits

<a id="dedup"></a>
## Duplicate findings

Independent agents converge on "lowest hanging fruit." The pipeline mitigates
this with a shared `found_bugs.jsonl` that agents populate during discovery
and deduplicate against before submitting. This doesn't eliminate all
collisions; a second run, feeding the first run's findings into
`config.yaml`'s `known_bugs`, helps agents avoid re-converging on the same
paths.

For interactive scanning, run `/triage ./VULN-FINDINGS.json` to collapse
duplicates and re-rank by derived exploitability.

<a id="rate-limits"></a>
## Rate limits

Rough guideline: ~10K uncached input tokens/min and ~2K output tokens/min per
agent. Scale parallelism to your account's ITPM: roughly **10 agents per
100K ITPM** as a starting point (check your limit in the
[Claude Console](https://console.claude.com/settings/limits)).

Bursting past your limit is not catastrophic: the pipeline resumes on 429
with full conversation context (see
[pipeline.md#rate-limits-and-resume-on-error](pipeline.md#rate-limits-and-resume-on-error)).
You should not need to throttle far below provisioned capacity.

<a id="skill-checkpoints"></a>
## Skill run died mid-way (large codebase)

`/threat-model bootstrap` and `/triage` write per-stage checkpoints to
`./.threat-model-state/` and `./.triage-state/` respectively, next to their
output. If a run dies on context exhaustion, rate limits, or Ctrl-C, **just
re-invoke the same command**; it reads `progress.json`, restores state from
the per-stage JSON files, and picks up at the next stage/phase without
re-spawning the research swarm or verifiers. Pass `--fresh` to discard the
checkpoint.

Checkpoint writes go through `.claude/skills/_lib/checkpoint.py` (atomic,
JSON-validated). The final output (`THREAT_MODEL.md` / `TRIAGE.md`) is
appended one section at a time, so a server-side stall mid-output loses that
one section instead of the whole file; the next re-invoke picks up from the
last complete stage.

<a id="pipeline-resume"></a>
## Pipeline run died mid-batch

```bash
vuln-pipeline run <target> --runs N --resume results/<target>/<ts>/
vuln-pipeline report results/<target>/<ts>/          # skips already-reported bugs
vuln-pipeline report results/<target>/<ts>/ --fresh  # force full re-report
```

`--resume` skips any `run_NNN` whose `result.json` reached a terminal status
(`crash_found`/`crash_rejected`/`no_crash_found`); `agent_failed`/
`build_failed`/`error` are retried. `found_bugs.jsonl` and `focus_areas.json` carry over so resumed runs
see the same dedup context. This is distinct from the per-agent
`--resume <session_id>` in `agent.py`, which restores transcript history
inside one CLI process; `--resume <dir>` survives a killed orchestrator.

## False positives

The most common cause isn't the model misreading code; it's the model
lacking your trust boundaries. It flags a bug because it assumes a client
sends bad values or an attacker controls a config file; the read is
correct, the threat model is wrong. If a whole class of findings is wrong
in the same way, write the missing assumption into
[`threat_model.md`](threat-model.md) ("we trust authenticated clients",
"config files are operator-controlled") and re-run before you reach for
more verifiers.

See [best-practices.md #11](best-practices.md#judge):
add a skeptical judge agent that adjudicates between the bug report and a
critique of it. The
model reliably downgrades its own findings when asked directly.

A common false-positive shape: the code path is real, but a mitigation
upstream or downstream (input validation in a calling service, a sanitizer
in a shared library) makes it unreachable. The model can't see what it
hasn't read. Give it the upstream layer (see the wishlist pattern in
[best-practices.md](best-practices.md)), or feed traces/logs so it can observe
the mitigation firing at runtime. A second-opinion pass with a different
model (as a validation ensemble, not a replacement) also catches some of
these.

Tune precision before recall. Get the false-positive rate down to where you
trust the output, *then* widen the net; teams that did it in that order
roughly doubled recall once precision was solid.

## Coverage and diminishing returns

If a first scan only touches a small fraction of the surface (one team
found their initial pass covered ~3% of API endpoints), the fix is usually
recon, not more find agents: bump the focus-area count, or feed an endpoint
inventory so recon partitions the full surface. Horizontally scaling find
agents without re-partitioning hits diminishing returns fast; they
converge on the same shallow bugs.

Two completeness signals worth tracking: lines-of-code touched across all
find transcripts, and QA-test coverage as a proxy (if the target has a test
suite, ask the model which surfaces have no tests; those are often the same
surfaces the scan missed). Feed the model your existing known-vulns list so
it doesn't burn budget rediscovering what's already in your tracker.

## Subagents using the wrong model

Claude Code may launch subagents on a lower-tier model than your main
session. Pin them:

```bash
export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>
```

Or set `model: inherit` in your subagent definitions. If anything requests a
model by tier name, you can also pin what each tier resolves to with
`ANTHROPIC_DEFAULT_HAIKU_MODEL`, `ANTHROPIC_DEFAULT_SONNET_MODEL`, and
`ANTHROPIC_DEFAULT_OPUS_MODEL`.

## Skills vs. pipeline: which should I use?

| | Interactive skills (`/threat-model`, `/vuln-scan`, `/triage`) | Pipeline (`vuln-pipeline`) |
|---|---|---|
| Setup | None (just Claude Code) | Python env + Docker + sandbox |
| Analysis | Static, read-only review | Dynamic, ASAN-instrumented execution |
| Best for | Scoping, triaging existing findings | Deep verified bugs, C/C++ (or ported) |
| Runs | Interactive | Interactive OR fully autonomous |
| Output | THREAT_MODEL.md / TRIAGE.md | Crashing input files + exploitability reports |

Start with the interactive skills. Move to the pipeline when you want execution-verified
PoCs or autonomous scale.
