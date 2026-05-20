# canary — fast iteration target

A deliberately vulnerable target with three planted bugs, one per "parser."
Exists so pipeline changes can be verified in ~6 minutes instead of multi-hour
runs against real codebases.

**This is not a real-world target.** No CVE, no disclosure, no upstream. The
bugs are planted, documented in `entry.c`, and trivially findable. Use it to
smoke-test the pipeline after changes, tune prompts, or validate that focus-area
steering, dedup, and the report pipeline work end-to-end.

## The three bugs

| Parser | Dispatch byte | Bug | ASAN signature |
|---|---|---|---|
| `parse_alpha` | `'A'` | Trusts input length field, `memcpy` into 8-byte heap buffer | `heap-buffer-overflow` (WRITE) |
| `parse_bravo` | `'B'` | Unbounded `memcpy` into 16-byte stack buffer | `stack-buffer-overflow` (WRITE) |
| `parse_charlie` | `'C'` | Early-free on sentinel `0xff`, falls through to write | `heap-use-after-free` (WRITE) |

Three distinct `(crash_type, top_frame)` tuples — dedup should group them
separately, a 3-agent run with focus-area steering should find all three.

## Quick start

```bash
vuln-pipeline run canary --runs 3 --parallel --stream --model <model>
```

The config already has the three focus areas baked in — no `--auto-focus`
needed. Expected wall time is ~6 minutes for a full find→grade→report cycle
on all three bugs.

## When to use it

- **After pipeline changes** — fastest way to check nothing broke
- **Prompt iteration** — small enough to run repeatedly while tuning
- **Pipeline validation** — exercises every stage (recon, find, grade, judge,
  report) with predictable inputs
- **First run on a new install** — confirms Docker, the Claude CLI, and the
  entry point all work before pointing at a real target

## What it doesn't test

Scale. Three shallow bugs with one-byte triggers won't exercise long-context
attention, adaptive scale-up, or the `<dup_check>` gate under real pressure.
For that, point at a real target.
