# Claude for Securing Source Code

A reference implementation for autonomous vulnerability discovery and
human-reviewed remediation with Claude. Not maintained and not accepting
contributions. For a lightweight SDK-only
walkthrough of the same recon → find → triage → report → patch loop, see the
[companion cookbook](https://platform.claude.com/cookbook/cybersecurity/vulnerability_detection_with_claude).

- **Claude Code skills**: `/quickstart`, `/threat-model`, `/vuln-scan`,
  `/triage`, `/patch`, `/customize`: interactive scoping, scanning, triage,
  and patching. Open this repo in Claude Code and run `/quickstart` to get
  oriented.
- **`harness/`**: the autonomous reference pipeline (recon → find → verify
  → report → patch), instantiated here for C/C++ memory corruption with Docker +
  ASAN and parallel agents. A **reference, not a product**: the shape, the
  prompts in `harness/prompts/`, and the two-container trust boundary are
  what you reuse. Run `/customize` to port it to your language, detector,
  or vuln class.

> ⚠️ **Security:** the interactive skills (`/quickstart`, `/threat-model`,
> `/vuln-scan`, `/triage`) only read and write files and are safe as long as
> you approve each tool use in Claude Code. `/patch` on static findings
> (`TRIAGE.json` / `VULN-FINDINGS.json`) is likewise file-only. `/customize`
> also edits pipeline source and can run validation commands. The
> autonomous pipeline (Step 2+), including `/patch` on pipeline results,
> **executes target code**. It ships a gVisor agent sandbox and refuses to
> spawn agents outside it; run `scripts/setup_sandbox.sh` once, then invoke
> via `bin/vp-sandboxed`. See [docs/security.md](docs/security.md) and
> [docs/agent-sandbox.md](docs/agent-sandbox.md).

> 🔒 **Want a managed option?** Anthropic offers
> [Claude Security](https://claude.com/product/claude-security), a hosted product
> that finds and fixes vulnerabilities in your source code across multiple
> projects. Claude Security scans your repository for vulnerabilities,
> applies a multi-stage verification pipeline to reduce false positives, and
> lets you manage findings through their lifecycle: triage, fix validation,
> and rapid fix generation.
>
> This repository is an open-source reference implementation based on general
> best practices for finding vulnerabilities using Claude. You can use it to
> build your own vulnerability finding pipeline, customize the logic, and it
> can be used with whatever access you have to Claude APIs (including
> Bedrock, Vertex, or Azure).

```bash
git clone https://github.com/anthropics/defending-code-reference-harness
cd defending-code-reference-harness
claude

> /quickstart
# → 30-sec intro + guided first run on the canary target

> /quickstart how do I port the pipeline to Java?
> /quickstart how do I triage all these bugs?
```

## Table of contents

- [**Threat model**](docs/threat-model.md) · Decide what counts before you scan; bootstrap + interview
- [**Prompting**](docs/prompting.md) · Task framing, scope, context, guardrails
- [**Pipeline**](docs/pipeline.md) · How it works: diagram, stages, CLI flags
- [**Security**](docs/security.md) · Sandboxing, what not to mount
- [**Agent sandbox**](docs/agent-sandbox.md) · gVisor isolation + egress allowlist for every agent
- [**Customize**](docs/customizing.md) · Port to my stack; which files change and why
- [**Triage**](docs/triage.md) · How do I go through these hundreds of findings?
- [**Patching**](docs/patching.md) · Generate and verify fixes for verified crashes
- [**Best practices**](docs/best-practices.md) · 18 principles (verifier, judge, severity, variance)
- [**Troubleshooting**](docs/troubleshooting.md) · Duplicates, rate limits, subagent model pinning
- [**Other uses**](docs/other-use-cases.md) · Patching, binary analysis, pentesting, bug chains
- [**Safeguards**](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) · Block for dangerous cyber work

---

## Ramp-up: from scanning to patching

|         |                                           |        |
|---------|-------------------------------------------|--------|
| **Day 1**   | Threat-model + first static scan + triage | [Step 1](#step-1-day-1-threat-model-scan-triage) |
| **Day 2**   | Run the reference pipeline on a C/C++ library | [Step 2](#step-2-day-2-run-the-autonomous-pipeline) |
| **Day 3-5** | Customize the pipeline for your target    | [Step 3](#step-3-day-3-5-customize-for-your-target) |
| **Week 2**  | Start autonomous scanning, triage, and patching | [Step 4](#step-4-week-2-start-scanning-triaging-and-patching) |

---

## Step 1 (Day 1): Threat-model, scan, triage

These skills only **read and write files** in your repo. As long as you run
Claude Code interactively and approve each tool use, no additional sandbox
is needed.

```bash
# One-time: pin every subagent to the model you want
export CLAUDE_CODE_SUBAGENT_MODEL=<model-id>
claude

# 0. Front door: intro + guided first run (same as the Quickstart above)
> /quickstart

# 1. Build a threat model first (aim before you shoot)
> /threat-model bootstrap targets/canary

# 2. Static scan, scoped by that threat model
> /vuln-scan targets/canary

# 3. Verify, dedupe, and rank what came back
> /triage targets/canary/VULN-FINDINGS.json

# 4. Generate candidate fixes for the verified findings
> /patch ./TRIAGE.json --repo targets/canary
```

Produces `THREAT_MODEL.md`, `VULN-FINDINGS.{json,md}`, `TRIAGE.{json,md}`,
`PATCHES/`. These are **static candidates**; for execution-verified crashes,
move to Step 2.

> **Note:** `/triage` may mark the canary findings as false positives via its
> "test/fixture code" exclusion rule, since `entry.c` self-identifies as a
> planted-bug fixture, and that's triage working as designed. To see the
> full confirm/dedupe/FP flow, run it on the built-in fixture instead:
> `/triage .claude/skills/triage/fixtures/canary-findings.json --repo targets/canary`,
> or point Step 1 at your own code.

→ Deeper: [docs/prompting.md](docs/prompting.md) ·
[docs/best-practices.md](docs/best-practices.md)

---

## Step 2 (Day 2): Run the autonomous pipeline

The pipeline finds, verifies, and reports crashes autonomously, steered by
the focus areas from your Step-1 threat model. Under the hood it's just
**three things**:

**1. A Docker image per target.** Each target ships a `Dockerfile` that
compiles the code with ASAN (the crash detector). The pipeline builds this
image automatically on first use; you just need Docker installed and the
pipeline itself set up:

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
export ANTHROPIC_API_KEY=sk-ant-...   # or CLAUDE_CODE_OAUTH_TOKEN; the pipeline requires one in env

# The pipeline auto-builds this on first recon/run, but you can build it yourself to see what's inside:
docker build -t vuln-pipeline-drlibs:latest targets/drlibs/
```

**2. Recon: map before you dig.** A lightweight agent reads the source tree
inside a network-isolated container (no execution yet) and proposes a
partition: *"here are 7 distinct input-parsing subsystems worth attacking
separately."* This becomes the `focus_areas` list, so parallel find-agents
each start somewhere different instead of all piling onto the same shallow
bug.

```bash
bin/vp-sandboxed recon drlibs --model <model-id>
# → prints a focus_areas: YAML block you can paste into targets/drlibs/config.yaml
```

**3. Run: the autonomous loop.** N find-agents in parallel, each in its own
isolated container, read source → craft malformed inputs → run the ASAN
binary → iterate until a crash reproduces 3/3. A separate grade-agent
verifies each crash in a clean container the finder never touched, and
exploitability reports stream out as bugs are confirmed.

> ⚠️ **`run` spawns an autonomous agent.** The pipeline runs each agent
> inside a gVisor container with egress restricted to the API; agent-spawning
> subcommands refuse to start outside it. See
> [docs/security.md](docs/security.md) and
> [docs/agent-sandbox.md](docs/agent-sandbox.md).

```bash
./scripts/setup_sandbox.sh   # one-time: installs gVisor, builds agent images, verifies isolation
bin/vp-sandboxed run drlibs --model <model-id> --runs 3 --parallel --stream
```

Results land in `results/drlibs/<timestamp>/`; with
`--stream` the first report appears in minutes under `reports/bug_NN/`.
**Drive it from a Claude Code session the first time**; the repo's
`CLAUDE.md` has per-stage guidance.

→ Deeper: [docs/pipeline.md](docs/pipeline.md) (full pipeline diagram, every
stage explained, CLI flags, rate-limit math)

---

## Step 3 (Day 3-5): Customize for your target

The reference pipeline is C/C++/ASAN, but its shape is generic: *agent crafts
input → runs target in sandbox → detector fires → second agent verifies →
third writes exploitability.* Porting it means swapping a few nouns, not
rebuilding the loop:

| Axis         | C/C++ demo                          | Your target (examples)                         |
|--------------|-------------------------------------|------------------------------------------------|
| Detector     | ASAN crash signature                | exception / canary file / DNS callback         |
| PoC shape    | crashing input file                 | HTTP request sequence / tx list / test harness |
| Target build | `targets/*/Dockerfile` (clang+ASAN) | your language's build in a container           |

Start by pointing the **Step-1 skills at your own code**. They're read-only,
so you can run them immediately and see real output before touching the
pipeline. The artifacts they produce (threat model, static findings) are what
ground the `/customize` interview:

```bash
# Ask the front door what porting looks like for your repo
> /quickstart how do I customize this for ~/code/my-service?

# Build a threat model of YOUR target (reads the code, drafts, then refines it with you)
> /threat-model bootstrap-then-interview ~/code/my-service

# Static scan: shows /customize which bug classes appear in your code
> /vuln-scan ~/code/my-service

# Triage the scan output: what's real, what's noise, what matters
> /triage ~/code/my-service/VULN-FINDINGS.json --repo ~/code/my-service

# Now port the pipeline, with those artifacts as context
> /customize use ~/code/my-service/{THREAT_MODEL.md,VULN-FINDINGS.json} and ./TRIAGE.md
```

When `/customize` is done you'll have `targets/my-service/` wired up; validate
it with `bin/vp-sandboxed run my-service --model <model-id> --runs 1` before scaling up.

→ Deeper: [docs/customizing.md](docs/customizing.md)

---

## Step 4 (Week 2): Start scanning, triaging, and patching

Step 3 left you with `targets/my-service/`: your build, your detector, your
prompts. Run the autonomous loop on it, triage the batch, patch the top of
the queue, and repeat. Same ⚠️ isolation rules as Step 2.

```bash
# Scan: the autonomous pipeline, now on YOUR target (via bin/vp-sandboxed)
bin/vp-sandboxed recon my-service --model <model-id>
bin/vp-sandboxed run my-service --model <model-id> --runs 5 --parallel --stream

# Triage: verify, dedupe, rank the batch
> /triage results/my-service/<timestamp>/ --repo ~/code/my-service --auto --votes 5

# Patch: static findings (no PoC), per-finding patch agent + independent reviewer
> /patch ./TRIAGE.json --repo ~/code/my-service --top 5

# Patch: pipeline findings (PoC + ASAN trace), delegates to the verification ladder
> /patch results/my-service/<timestamp>/ --model <model-id>
# or call the pipeline directly:
bin/vp-sandboxed patch results/my-service/<timestamp>/ --model <model-id>
```

`/triage` on a pipeline batch collapses duplicates across runs, re-ranks by
derived exploitability (not the scanner's claimed severity), and routes each
finding to a component owner, so engineering gets a short, ranked, owned
list instead of a dump.

`/patch` is the unified entry point for fix generation. On pipeline input
each diff is graded in a fresh container by an executable ladder (apply +
build, original PoC stops, regression suite still passes, fresh find-agent
re-attacks the patched binary) and labeled `verified: "ladder_passed"`. On
static input there is no executable oracle; diffs are reviewed by an
independent agent that sees only the diff and the source location, and
labeled `verified: "static_review_only"`.

Either way the diff is a draft. Read it before upstreaming; see
[docs/patching.md](docs/patching.md#reviewing-generated-patches) for what to
look for, and the same doc for porting the verification ladder to non-C/C++
targets.

→ Deeper: [docs/triage.md](docs/triage.md) · [docs/patching.md](docs/patching.md)

---

## Best practices

**Map the system before you scan it.** On a large codebase, first have
Claude read the whole thing and distill a system design and threat model:
how the components fit together, where trust boundaries sit, what's exposed.
Use that map to prioritize which services to scan first, and run the pipeline
component-by-component. Once the individual pieces are clean, do a pass
across the whole system for bugs that only appear when components chain
together. `/threat-model bootstrap` is built for this first pass.

**Give Claude as much context as you can.** Teams have gotten a lot of
mileage from pointing Claude at their research docs, design docs, git
history, and even internal portals alongside the code. The extra context
lets Claude connect how components interact and what's changed over time,
which is where the non-obvious bugs live.

**Don't prescribe how to hunt; give context and step away.** Claude
often finds vulnerabilities in ways a human researcher wouldn't, and that's
fine. Long instructions, staged checklists, and piles of reference material
usually backfire: the model pattern-matches your scaffolding instead of
reasoning about the code. Give it the target, the goal, and the tools; let
it choose the path.

**Divide the work cleanly.** Parallel agents converge on the same shallow
bugs unless you partition the search space first. A recon step that tells
each agent precisely which part of the codebase to search, and what to look
for, is the most effective way to avoid duplication.

**Invest in killing false positives fast.** The verifier is the
load-bearing component. Layer a cheap programmatic gate
(sanitizer signal, parse check, reproduces 3/3) in front of an adversarial
grader agent running in a clean sandbox, and prefer executable witnesses (a
crash, a leaked value) over written arguments.

→ Deeper: [docs/prompting.md](docs/prompting.md) · [docs/best-practices.md](docs/best-practices.md)

## Advanced tips

**Feed it your existing backlog first.** Before hunting new bugs, point the
model at your current pile of open findings (older scanners, prior models,
bug-bounty intake) and have it downgrade or disprove what it can. Teams have
cleared hundreds of stale items this way and used the survivors to calibrate
severity scoring before the new findings arrived.

**Give it a live sandbox, not just source.** Source plus a running
environment (HTTP traffic, logs, a seeded database, an emulator) lets the
model chain findings into context-aware exploits instead of stopping at
static reports. The deepest results come from teams that let it execute,
observe, and iterate.

**Expect variance; union across runs.** The same prompt on the same target
won't return identical findings or identical severities. Treat each run as a
sample: run several, union the results, and don't trust any single pass.

**Use a judge agent to whittle the list down.** When the pile is large, have
a second agent critique each finding and a third adjudicate between report
and critique; the model reliably downgrades its own findings when asked
directly. `/triage` packages this loop.

**Don't wait for a perfect pipeline.** Start scanning, let the model tell you
what's missing, and fold the lessons back in. Teams that iterate on the
pipeline from real transcripts move faster than teams that try to design it
right up front. A `CHEATSHEET.md` that records what worked, fed back into
the prompt, compounds quickly.

**For open-source targets, coordinate disclosure.** Route validated
Critical/High findings through an OSS coordination body rather than direct
to maintainers, and hold Low/Medium; uncoordinated vuln dumps burn
maintainer goodwill and get ignored.

