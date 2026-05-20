# Customizing the pipeline

The reference pipeline is a proof of concept for C/C++ libraries with ASAN. Its
real shape is more general: **an agent crafts an input, runs a target in a
sandbox, a detector fires, a second agent verifies, a third agent analyses
exploitability.** Every noun in that sentence can be swapped.

## Start here

Inside Claude Code, from the repo root:

```
> /customize
```

The `/customize` skill reads the
pipeline source, interviews you about your target (language, detector, build
system, vuln classes), and proposes a concrete migration plan. If you can't
use Claude Code, paste the contents of `.claude/skills/customize/SKILL.md`
into another AI coding tool.

## Example: porting to another language

For example, porting the pipeline to Java is mostly a new Dockerfile and a
detector swap; the find prompt often works as-is on JVM targets. The
fastest path is usually to open the repo in Claude Code, describe your
target environment, and let Claude adapt the prompts and scaffolding.

Most likely, extending this pipeline will mean building container images for
other kinds of software. This can be done manually or with in-house
processes, as long as the end result is that the vulnerability-finding agents
can inspect and run the target code in reproducible containers. When scaling
vulnerability-hunting across many libraries, we've found it invaluable to
delegate *this* task to an agent too: installing open-source software is
tedious, and a sandboxed agent with a frontier model is effective at
producing fully-working builds.

Once the target software is runnable in a container, spin up a few
vulnerability-finding agents in parallel to speed up time-to-results. While
interactive investigation in Claude Code helps, results scale massively with
effective autonomous agents. A great way to iterate on these agents is to use
Claude Code to review their transcripts and suggest improvements to the
pipeline and prompt; this is a far better use of time than trying to find
vulns interactively.

**It's fine to run more than one pipeline.** Some teams maintain a few
opinionated variants (one tuned for the most capable model, one that
breaks the problem into much smaller pieces for a cheaper model, one for a
specific bug class) and union the results. The point isn't the number; it's
that a single pipeline encodes one set of assumptions, and a second one with
different assumptions catches different things.

## Lighter-weight: tune the interactive skills

If you don't need a full port and just want `/vuln-scan` and `/triage` to
understand your stack, both take a plain-text instructions file:

```
> /vuln-scan ./src --extra .claude/scan-extras.txt
> /triage ./VULN-FINDINGS.json --fp-rules .claude/fp-rules.txt
```

`--extra` appends org-specific vulnerability categories to the scan brief
(GraphQL depth attacks, PCI retention, your custom auth layer). `--fp-rules`
appends org-specific exclusions to the triage verifier ("we use Prisma
everywhere, raw-query SQLi only", "k8s resource limits cover DoS"). Keep
both files in version control alongside your code.

## What to change, concretely

The C/C++-specific parts live in:

- `harness/prompts/find_prompt.py`, `harness/prompts/grade_prompt.py`: bug
  taxonomy, quality tiers, grading rubric
- `harness/prompts/report_prompt.py`, `harness/prompts/report_grader_prompt.py`:
  exploitability sections (primitive, heap layout, escalation path) and the
  rubric that scores them
- `targets/<target>/Dockerfile`: build + detector (ASAN) setup

The orchestration (`harness/cli.py`, `harness/find.py`, `harness/grade.py`,
`harness/report.py`) is mostly generic plumbing and usually survives a port
with minimal changes.

See [pipeline.md](pipeline.md) for the architecture, and
[troubleshooting.md](troubleshooting.md) for the pitfalls you'll hit along
the way.
