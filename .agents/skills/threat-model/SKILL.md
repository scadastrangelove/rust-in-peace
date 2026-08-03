---
name: threat-model
description: >-
  Build a threat model for a target codebase. Three modes: "interview" walks an
  application owner through the four-question framework and produces a threat
  model from their answers; "bootstrap" derives a threat model from the code
  plus past vulnerabilities (CVEs, git history, pentest reports) when no owner
  is available; "bootstrap-then-interview" chains the two when both owner and
  codebase are present. All write THREAT_MODEL.md in a shared schema. Use
  when asked to "threat
  model", "build a threat model", "map the attack surface", or "what should we
  be worried about in this codebase".
argument-hint: "[bootstrap-then-interview|bootstrap|interview] <target-dir> [--vulns <file>] [--design-doc <file>] [--seed <THREAT_MODEL.md>] [--fresh]"
allowed-tools:
  - Read
  - Glob
  - Bash(python3 .Codex/skills/_lib/checkpoint.py:*)
  - Grep
  - Write
  - Bash(git:*)
  - Bash(gh api:*)
  - Bash(find:*)
  - Bash(ls:*)
  - Bash(cat:*)
  - AskUserQuestion
  - Task
---

# threat-model

A threat model answers **"what could go wrong with this system, who would do
it, and what should we do about it?"** independently of whether any specific
bug has been found yet. It is the map; vulnerability discovery is the metal
detector. A good threat model tells the pipeline where to look and tells triage
which findings matter.

**Litmus test:** If patching one line of code makes an entry disappear, it was
a vulnerability, not a threat. A threat ("attacker achieves memory disclosure
via untrusted binary parsing") still stands after every known bug is fixed; a
vulnerability ("`Table::sum_record` reads an `unsafe` slice at an
attacker-controlled `data_off` without a bounds check") does not. This skill
produces threats. Vulnerabilities appear only as **evidence** that raises a
threat's likelihood score.

**Invocation:** `/threat-model [bootstrap-then-interview|bootstrap|interview] <target-dir> [flags]`

---

## Step 0 — Safety preamble (always runs first)

This skill performs **static analysis only**. It reads source, git history,
and any vulnerability reports the user supplies, and writes a single output
file (`<target-dir>/THREAT_MODEL.md`). It does not build, execute, fuzz, or
modify the target, and does not make network requests against the target's
infrastructure.

Before proceeding, confirm and state in your first response:

1. The target directory exists and is a local checkout you can read.
2. You will not execute any code from the target directory.
3. If `--vulns` points at a URL or you are asked to "fetch CVEs", you will
   query only public advisory databases (NVD, GitHub Security Advisories, the
   project's own issue tracker) and never the target's live deployment.

If the user asks you to validate a threat by running an exploit, decline and
point them at the `vuln-pipeline` (README Step 2) instead.

---

## Step 1 — Route to a mode

Parse `$ARGUMENTS`:

| First token | Route to |
|---|---|
| `interview` | Read `interview.md` in this directory and follow it. |
| `bootstrap` | Read `bootstrap.md` in this directory and follow it. |
| `bootstrap-then-interview` | Bootstrap first, then interview seeded from the draft. See below. |
| anything else, or empty | Ask the user: **"Is someone who owns or built this system available to answer questions in this session?"** Yes and the codebase is checked out → recommend `bootstrap-then-interview`. Yes but no codebase → `interview.md`. No → `bootstrap.md`. |

All modes write the same artifact (`THREAT_MODEL.md`, schema in `schema.md`)
so downstream consumers (pipeline `recon`/`judge`, verifier agents) do not need
to know which mode produced it.

| | `interview` | `bootstrap` |
|---|---|---|
| **Needs** | An application owner present in the session | A local checkout; optionally past vulns |
| **Method** | Four-question framework: conversational walk through *what are we working on → what can go wrong → what are we going to do about it → did we do a good job* | Five stages: parallel research swarm → synthesize sections 1-3 + vuln table → generalize vulns into threat classes → STRIDE gap-fill → emit |
| **Best for** | New systems, design reviews, systems where the risk lives in business logic the code doesn't show | Inherited systems, third-party code, OSS dependencies, anything with a CVE history |
| **Provenance tag** | `interview` | `bootstrap` |

**Context durability.** Interview mode is multi-turn; tool results from early
reads may be evicted before you need them. To stay resilient:

- Do **not** read `interview.md` or `bootstrap.md` in full up front. Read the
  mode file (or the relevant section of it) **at the point you need it**, one
  question or stage at a time.
- If a re-read via the Read tool is refused as "file unchanged", the prior
  result was evicted; reload with `cat <path>` via Bash instead.

**Interview backbone** (so you can proceed even if `interview.md` is
unavailable mid-session):

| Q | Question | Fills schema sections |
|---|---|---|
| Q1 | What are we working on? | section 1 context, section 2 assets, section 3 entry points |
| Q2 | What can go wrong? | section 4 threat rows (id, threat, actor, surface, asset) |
| Q3 | What are we going to do about it? | section 4 impact/likelihood/status/controls; section 5 deprioritized; section 8 recommended mitigations |
| Q4 | Did we do a good job? | validate ranking, coverage check, section 6 open questions |

### `bootstrap-then-interview` mode

When the owner is available *and* the codebase is checked out, this is the
recommended path: the owner's time goes to refining a code-grounded draft
instead of describing the system from scratch.

1. Tell the owner: "I'll read the code first and come back with a draft
   (about 5-10 min), then we'll walk it together. Want that, or would you
   rather start cold?" Only proceed if they opt in; otherwise fall back to
   `interview.md`.
2. Read `bootstrap.md` and follow it end-to-end. Write
   `<target-dir>/THREAT_MODEL.md`.
3. Immediately continue into interview mode: read `interview.md` and follow
   it with `--seed <target-dir>/THREAT_MODEL.md` in effect. The section 6 open
   questions from bootstrap become your Q1-Q4 prompts; the owner confirms,
   corrects, and adds rather than starting from nothing.
4. Overwrite `<target-dir>/THREAT_MODEL.md` with the refined model. Set
   provenance `mode: bootstrap-then-interview`.

The same flow is available manually: run `bootstrap` first, then
`interview --seed <THREAT_MODEL.md>` in a later session.

---

## Step 1.5 — Classify the target's LAYER (bug-class & tool router) `[ADR-1]`

Before deriving threats, classify the target into ONE layer and record it as `target_layer` in
section 1. The layer decides the primary bug-class to hunt and the primary tool — routing this
deliberately is the difference between finding the class that ships and re-running a fuzzer over
already-fuzzed code (see `LESSONS.md` L42–L44).

| Layer | Signal | Primary bug-class | Primary method | Add finders |
|---|---|---|---|---|
| **data-format parser** | bytes → structure; a `decode`/`parse`/`from_bytes` entry over untrusted input | panic / OOB / overflow / alloc-DoS on malformed input | **fuzz-first** | classic cargo-fuzz + `find→fuzz` CWE→oracle table |
| **protocol / state-machine** | handshakes, sessions, negotiated params, client+server sides | missing/asymmetric enforcement, downgrade, state-transition data-loss, protocol-tied resource growth | **invariant-first** | invariant-symmetry + silent-failure differential |
| **API-contract / library** | serialization, containers, config, fs helpers; a documented contract | contract violation, silent failure, spec/impl divergence | **differential-first** | spec-vs-impl + control-vs-attack differential |

Rules:

- **Fuzz only when** layer = parser (or a parser sub-surface) **and** not already well-covered by
  OSS-Fuzz **and** the class is crash/OOB/alloc. Otherwise deprioritize byte-mutation fuzzing and
  record *why* in section 5 (deprioritized) — a decision, not an omission.
- **Protocol/contract targets:** enumerate the protocol's **invariants** (e.g. "QUIC uses TLS 1.3
  only", "chunked framing terminates on a zero-size line", "recursion is bounded") and, for each,
  locate **where it is enforced and where its mirror is not** (client↔server, send↔receive,
  offered↔accepted, one-param↔all-params). A guard with a missing mirror is a section-4 threat with a
  concrete evidence lead. Silent-failure bugs (validated-then-discarded, accept-what-should-reject)
  need a control-vs-attack oracle, not a crash — flag them for that harness.
- **Release-diff is mandatory.** If the checkout is a dev pin, note the latest released tag and flag
  which threats are shipped vs dev-only-new vs a dev *regression* of a shipped guard — this changes
  both severity and disclosure channel.
- A large target can be **multi-layer** (rustls = protocol core + a `msgs/` parser sub-surface):
  classify per sub-surface and route each.

Then continue to the mode from Step 1; the layer + hunt plan feeds `bootstrap`'s "generalize vulns
into threat classes" stage.

---

## Step 2 — Shared output contract

All modes MUST emit `<target-dir>/THREAT_MODEL.md` conforming to `schema.md`
in this directory. **Read `schema.md` immediately before you write the file**,
not at routing time; in interview mode the gap between routing and emit can be
many turns, and an early read will be evicted before it's used.

After writing the file, print to the user:

1. The path to `THREAT_MODEL.md`.
2. The top 5 threats by likelihood × impact (id, one-line description, L×I).
3. For `bootstrap`: any open questions the code could not answer (these seed a
   later `interview` pass).
4. For `interview`: any owner statements that could not be verified in code
   (these seed follow-up code review).

---

## References

- [docs/security.md](../../../docs/security.md) for the engagement-context,
  authorization, and untrusted-input framing this skill inherits.
