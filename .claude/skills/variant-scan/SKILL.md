---
name: variant-scan
description: >-
  Seed-diverse multi-pass find: run the same target through THREE independent
  find passes — blind, threat-model-first, and CVE/history-seeded — union the
  candidates with vote-counting, then hit each with a 3-skeptic adversarial
  verify panel (correctness / reachability / impact). This is the recall engine
  the real-OSS campaigns were run on; it complements /vuln-scan (single-pass
  focus-area fan-out) rather than replacing it. Use when asked to "run the three
  passes", "variant scan", "blind + threat-model + CVE-seeded", "find everything
  in <crate>", or when a target has known history (CVEs/RUSTSEC) worth seeding
  from. Read-only. Its dispositions are TRIAGE, not verdicts — every survivor
  still needs an independent PoC (see the discipline gate below).
argument-hint: "<target-dir> [--passes blind,tm,cve] [--seed-cves <file>] [--focus <area>]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Workflow
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
  - Bash(file:*)
---

# /variant-scan

Three seed-diverse find passes over one target, unioned, then adversarially
verified. This is the workhorse that ran every real-OSS campaign
(x509-parser, lopdf, zune-jpeg, object, gimli, httparse, quick-xml,
miniz_oxide, ciborium, png/image, rmp-serde, ttf-parser, gitoxide). Until now
it lived only as a scratchpad workflow script; this skill is its permanent home.

**Why three passes and not one.** They have *different* strengths and
converge only on the "big" bug — everything else, each finds alone
(`LESSONS.md` **L21, L25**; the design note is [`docs/variant-analysis.md`](../../../docs/variant-analysis.md)):

- **blind** — generic "find security bugs", no class hint. Catches whole
  bug-classes a threat model didn't anticipate.
- **threat-model-first** — lenses seeded from `THREAT_MODEL.md` §3 (entry
  points, trust boundaries, the declared defect-origin class). Reaches depth
  and differential surface a blind pass skips.
- **CVE/history-seeded** — variant analysis ("bugs travel in packs"): for each
  historical advisory/CVE/RUSTSEC on this crate *or a sibling*, extract the
  **pattern** (not the specific bug) and hunt the same pattern in code paths the
  original fix didn't cover. Seed from confirmed **and refuted** prior findings
  too — control coverage is non-uniform. This is where net-new siblings of
  already-patched bugs come from.

Run **all three by default** and union. Dropping one to "save budget" is the
one optimization L25 explicitly warns against.

## Arguments

- `<target-dir>` (required) — source tree to scan.
- `--passes blind,tm,cve` — which seed sources to run (default: all three).
- `--seed-cves <file>` — a list of advisory IDs / patterns to seed the CVE pass
  (else derive from `THREAT_MODEL.md`, `capabilities.json`, and a quick
  RustSec/GitHub-advisory lookup for the crate + siblings).
- `--focus <area>` — restrict all passes to one subsystem (repeatable).

## How it runs

Each pass is one invocation of the reference orchestration
[`find_engine.mjs`](find_engine.mjs) (for the **Workflow** tool), with that
pass's lenses:

1. **Find** — N lens-agents in parallel, each emitting `FIND_SCHEMA` findings
   (`bug_class, file, line, symbol, mechanism, reachability_from_entry,
   poc_sketch, severity, confidence`).
2. **Union-of-N dedup** — collapse by `bug_class-prefix @ file:symbol`,
   counting votes across lenses.
3. **Verify** — per candidate, 3 skeptic lenses (**correctness / reachability /
   impact**), each told to *refute* and to cite a concrete `where_checked`
   (`file:line` of the guard, or of the unguarded path). Disposition:
   `confirmed` (≥2 real&&reachable), `contested` (1), `refuted` (0 but voted),
   `unverified` (no verifier returned — e.g. an infra failure).

Then **union the three passes** the same way (dedup by the same key across
passes; a candidate found by two seed sources is the strongest signal it's
real, not a seed artifact).

Without the Workflow tool, run the same shape with plain `Task` subagents: N
finders → dedup in-message → 3 verifiers per candidate → same disposition rule.

## The discipline gate — dispositions are TRIAGE, not verdicts

**This is the point of the skill, not a footnote.** A `confirmed` from the vote
panel means "worth your time", never "it's real". Every campaign that skipped
this gate shipped a false positive:

- **gitoxide tar-slip** — 3/3 unanimous "confirmed HIGH" (and 2/3 on a second
  pass). Refuted only by building an independent PoC and running it: the `tar`
  crate's own `..`-guard and `rawzip`'s path-normalization, plus an
  `index_from_tree` gate upstream, all sat on the path the verifiers never
  traced. (JOURNAL, gitoxide Stage 3.)
- **x509 RSA over-claim** — "confirmed" by both a finder and a curator layer;
  refuted by reading that `asn1-rs` rejects the input and the sink re-parses
  (`LESSONS.md` L1/L8, the two-layer over-claim).
- **gitoxide NTFS `git~1` / `protect_hfs` asymmetries** — looked novel; a
  faithful port of real git's own code once compared against upstream `path.c`.

So before any survivor is called real:

1. **Read the actual verifier text**, not the vote count. `find_engine.mjs`
   carries `verifier_reasons` for exactly this — one skeptic lens is often
   right and outvoted 2-to-1.
2. **Build an independent PoC** (or read the gating call site end-to-end) that
   exercises the finding through the *real* entry point on crafted/untrusted
   input. Construction-via-builder-API is not parse-reachable (L12).
3. **Verify against the actual shipping target** — release AND current default
   branch, plus the maintainer's own tests/docs — before treating it as
   reportable (L15/L32).
4. Treat `unverified`-from-infra-failure as **no signal**, not tacit
   refutation — re-run verify or hand-check the highest-severity ones.

Only what survives 1–3 goes downstream to `/triage` → `grade`/reattack
(execution-verified) → `predisclose`.

## Output

Per pass and for the union: `confirmed / contested / refuted / unverified`
lists, each candidate carrying `lenses`, `votes`, `real_votes`, `where_checked`,
and `verifier_reasons`. Write `VARIANT-FINDINGS.json` (+ `.md`) in the same
shape `/triage` ingests, with a per-candidate `disposition` and an explicit
`independently_verified: false` until step 2 above is done by hand.

## Relationship to the rest of the pipeline

`/variant-scan` is the recall front-end (static, read-only, multi-pass). It
feeds `/triage`; execution-verification still happens in `vuln-pipeline`
(`grade`, the find→fuzz reattack bridge, `run_crash_track`). It does **not**
replace `/vuln-scan` — use `/vuln-scan` for a quick single-pass focus-area
review, `/variant-scan` when you want maximum recall and the target has history
worth seeding from.
