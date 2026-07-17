# Customizing the pipeline

The pipeline ships two worked profiles — `rust` (Miri / ASan / panic / hang +
cargo-fuzz) and the base `cpp` (ASan) — but its overall shape is general.
Supporting another language or bug class means adding a profile: a new
`harness/<lang>/` package and one registry entry, updating only the parts that
are language- and detector-specific. The `rust` profile in `harness/rust/` is a
complete worked example of exactly this.

## Start here

Inside Claude Code, from the repo root:

```
> /customize
```

The skill reads the pipeline source, interviews you about your 
target (the language, how a finding is detected, the build system, which vuln
classes you care about), and proposes a concrete migration plan. If you can't
use Claude Code, paste the contents of `.claude/skills/customize/SKILL.md`
into another AI coding tool.

## Profiles: the built-in way to add a language

The pipeline now has a **profile registry** (`harness/profiles.py`). A profile
bundles the pieces that vary by language/detector — find prompt, crash detector,
and grade/judge/report/patch prompt builders — and every stage resolves them at
run time from a `profile:` field in the target's `config.yaml` (default `cpp`).

This means a language port no longer edits the base `harness/prompts/*` or
`harness/asan.py` in place. Instead you **add** a package and one registry entry:

1. Create `harness/<lang>/` with `find_prompt.py`, `detect.py` (the crash
   detector — same surface as `asan.py`: `project_frames`, `top_frame`,
   `crash_reason`, `asan_excerpt`), and any forked prompt builders
   (`grade_prompt.py`, `judge_prompt.py`, `report_prompt.py`, `patch_prompt.py`).
   Reuse the base builders for whatever doesn't need to change.
2. Add one `Profile(...)` entry to `harness/profiles.py`.
3. Set `profile: <lang>` in your target's `config.yaml`.

The generic orchestration (`cli.py`, `find.py`, `grade.py`, `judge.py`,
`report.py`, `patch.py`, `dedup.py`) does not change — it already calls
`get_profile(target.profile).build_...(...)`. Keeping the base `cpp` profile
untouched lets you run both and union results.

**`rust` is a complete worked example** of such a port: see
[`profiles/rust/README.md`](../profiles/rust/README.md), the `harness/rust/`
package, and the `targets/rust-canary` demo target. It swaps ASan for a
Miri / sanitizer / panic / hang detector and retargets the whole taxonomy to
Rust (unsafe/FFI memory safety, panic-DoS, deserialization trust). Read it
before porting a new language — it shows exactly which pieces are worth forking
and which reuse the base.

The sections below describe the C/C++ specifics file-by-file; a fork edits the
*copies* under `harness/<lang>/`, not these originals.

## What a port usually involves

Most likely, porting this pipeline will mean building container images for
new software stacks. This can be done manually or with your standard processes,
as long as the end result is that the pipeline agents can inspect and run
the target code in reproducible containers. When scaling vulnerability-hunting
across many codebases, delegating *this* task to an agent too is invaluable:
setting up images is tedious, and a sandboxed agent with a frontier model is
good at producing fully-working builds.

A great way to iterate and improve on a given port is to use Claude Code to 
review the transcripts from past runs and suggest improvements to the
pipeline and prompts.

**It's fine to run more than one pipeline.** Many teams maintain a few
opinionated variants (one tuned for the most capable model, one that
breaks the problem into much smaller pieces for a cheaper model, one for a
specific bug class) and union the results. A given pipeline encodes a
set of assumptions (explicitly or implicitly) and adding variants with
different assumptions will catch different things.

## Where the C/C++ specifics live, concretely

1. Find and grade (`harness/prompts/find_prompt.py` and `harness/prompts/grade_prompt.py`):
What the find agent hunts for and what the grader accepts as a real crash.
In the find prompt, mainly the "Crash Quality Tiers" and "Out of Scope"
sections, plus the crash fields in the output format. In the grade prompt,
the five-criteria rubric.
2. Report and report grader (`harness/prompts/report_prompt.py` and `harness/prompts/report_grader_prompt.py`):
The sections of the exploitability report and the rubric that scores those
sections currently assume memory corruption (heap layout, escalation path).
3. Patch and patch grader (`harness/prompts/patch_prompt.py` and `harness/patch_grade.py`):
How a fix is requested and what counts as fixed.
4. Crash signatures (`harness/asan.py`): How detector output is turned
into signatures for deduplication.
5. The target itself (`targets/<target>/Dockerfile`): How the target is
built with a detector active, along with its build and test commands.

The orchestration (`harness/cli.py`, `harness/find.py`, `harness/grade.py`,
`harness/report.py`) is mostly generic plumbing and usually survives a port
with minimal changes.

## Tune the interactive skills

If you don't need a full port and just want `/vuln-scan` and `/triage` to
understand your stack, both take a plain-text instructions file:

```
> /vuln-scan ./src --extra .claude/scan-extras.txt
> /triage ./VULN-FINDINGS.json --fp-rules .claude/fp-rules.txt
```

`--extra` appends org-specific vulnerability categories to the scan brief
(e.g., GraphQL depth attacks, PCI retention, your custom auth layer).

`--fp-rules` appends org-specific exclusions to the triage verifier (e.g., "we use Prisma
everywhere, raw-query SQLi only", "k8s resource limits cover DoS").

If you use these files to tune the skills, keep them in version control
alongside your code.
