---
name: quickstart
description: >-
  The front door for this repo. With no argument: a 30-second
  intro, then an offer to walk you through your first run on the canary
  target. With a question: answers it from this repo's own docs and source,
  cites where it looked, and hands you the next command. Use for "how do
  I…", "why does…", "where is…", "can this…", or just "/quickstart" to get
  oriented.
argument-hint: "[question]   (blank = 30-sec intro)"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Task
  - AskUserQuestion
---

# /quickstart

Two modes, picked by whether `$ARGUMENTS` is empty.

- **Empty → Intro mode.** Short orientation, then offer the guided first run.
- **Non-empty → Help mode.** Treat `$ARGUMENTS` as the operator's question.

---

## Intro mode

Keep it short and a little warm; this is the first thing a new operator sees.

Say roughly:

> **Welcome!** This repo takes you from finding your first vulnerability to
> patching at scale, using a set of Claude Code skills and an autonomous
> pipeline. It's **rust-first** — the headline is the `rust` profile
> (Miri/panic/hang detectors + cargo-fuzz, capability-routed fuzzing,
> find→fuzz reattack, the scorecard) — with a fully retained C/C++ + ASan
> base. Two ways in: **interactive skills** (no setup, safe, start here)
> and the **autonomous pipeline** (Docker, scales to hundreds of parallel
> agents).
>
> The ramp-up:
>
> | Day 1   | Threat-model + first static scan + triage |
> | Day 2   | Run the reference pipeline (rust-canary; cpp base also available) |
> | Day 3-4 | Customize it for your stack               |
> | Week 2  | Autonomous scanning, triage, and patching |
>
> Day-1 goal: threat-model, scan, and triage the bundled canary target.
> Most teams get there before lunch.

Remind them to `export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>` so subagents
use the same model as the session.

Then **AskUserQuestion** with three options:

1. **Walk me through Day 1 on the canary (~10 min)** → run "Guided first
   run" below.
2. **I have a question** → ask what it is, then switch to Help mode.
3. **I'll read the README** → point at `README.md` Step 1 and stop.

### Guided first run

Runs the three Step-1 skills on `targets/rust-canary` (the rust-first
default), pausing after each to show what landed on disk. These only
read/write files in the repo; no sandbox needed. Prefer rust-canary; offer
`targets/canary` (the cpp base) if the operator's stack is C/C++.

1. `/threat-model bootstrap targets/rust-canary` via Task. When done, open
   `targets/rust-canary/THREAT_MODEL.md`, show the focus areas, explain in
   2-3 sentences how this steers the scan.
2. `/vuln-scan targets/rust-canary/crate --extra profiles/rust/scan-extras.txt`
   via Task (the canonical rust invocation — `scan-extras.txt` adds the
   Rust vuln classes to the brief). When done, open
   `targets/rust-canary/crate/VULN-FINDINGS.md`, summarize the count and top
   2-3 findings, point at `VULN-FINDINGS.json`.
3. `/triage targets/rust-canary/crate/VULN-FINDINGS.json --repo targets/rust-canary/crate --fp-rules profiles/rust/fp-rules.txt`
   via Task (`fp-rules.txt` carries the R1–R11 rust precedents). When done,
   open `TRIAGE.md`, explain what changed vs. raw findings (verified,
   deduped, re-ranked).

   For the cpp base instead, drop the `--extra`/`--fp-rules` files and point
   at `targets/canary`.

Pause for the operator between each (AskUserQuestion); don't barrel through.
Close with a one-line recap of the three artifacts on disk, then point at
README Step 2 for the execution-verified pipeline. **Never run `vuln-pipeline`
or anything that executes target code here**; that's Step 2 and needs
Docker + a sandbox.

---

## Help mode

Answer the operator's question using **this repo as ground truth**: README,
`docs/*.md`, `harness/*.py`, `targets/*/config.yaml`, `.claude/skills/*`.
Don't answer from general knowledge when the repo has a specific answer.

### Routing map

| If the question is about…       | Read first                              | Then offer |
|---------------------------------|-----------------------------------------|------------|
| running the pipeline             | `docs/pipeline.md`, README Step 2        | the `recon` / `run` command |
| too many findings, triage       | `docs/triage.md`                        | `/triage <path>` |
| the rust profile, rust-canary   | `profiles/rust/README.md`               | run `rust-canary` |
| the android-app profile, APK, decompiled DEX, MASVS/MASTG | `profiles/android-app/README.md`, `docs/profiles/android/DECISIONS.md` | run `android-canary`; `/vuln-scan <decompiled> --extra profiles/android-app/scan-extras.txt`, `/triage … --fp-rules profiles/android-app/fp-rules.txt` |
| capability routing, which checks run | `profiles/rust/capabilities.md` / `profiles/android-app/capabilities.md` | cite the capability→check map |
| reattack, find→fuzz, promoting findings | `profiles/rust/find-to-fuzz.md` | `vuln-pipeline reattack <results>` |
| scorecard, discipline gate, union-of-N | `profiles/rust/README.md`, README Step 2 | `vuln-pipeline scorecard <results>` |
| porting, adding a profile, Java/Go/etc. | `docs/customizing.md`, README Step 3 | `/customize` |
| safety, sandbox, Docker         | `docs/security.md`                      | cite; no action |
| rate limits, 429, token budget  | `docs/pipeline.md`: Rate limits, `docs/troubleshooting.md#rate-limits` | cite the numbers |
| duplicates, dedup               | `docs/troubleshooting.md#duplicate-findings` | `known_bugs:` hint |
| CLI flags, "what does --X do"   | `harness/cli.py` (grep the argparse)    | exact flag + example |
| which model, subagent pinning   | `docs/troubleshooting.md`: Subagents    | the `export` line |
| best practices, prompting       | `docs/best-practices.md`, `docs/prompting.md` | cite the principle |
| "how do I start"                | README Step 1                           | offer Guided first run |
| patching, fix, diff, re-attack  | `docs/patching.md`, README Step 4       | `/patch <input>` |
| binary, pentest, other domains  | `docs/other-use-cases.md`               | cite section |
| anything else                   | README Table of contents                | best-match doc |

### Answer format

1. **Direct answer** in 2-5 sentences.
2. `> source:` the file(s) and section you used.
3. **Next action:** one copy-pasteable command or skill invocation, if one
   applies. If none does, say so.
4. If the question is ambiguous, ask **one** clarifying question; don't guess.

### Constraints

- Never fabricate CLI flags or file paths. If unsure, `Grep` for it in
  `harness/cli.py` or the target configs and quote what you find.
- If the repo doesn't answer the question, say so plainly and suggest the
  operator open a GitHub issue on this repo.
- Keep the Q&A dry and cited. Save the warmth for Intro mode.
