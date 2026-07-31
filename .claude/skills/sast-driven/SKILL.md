---
name: sast-driven
description: >-
  The SAST-driven find mode — a fourth, deliberately ISOLATED pass alongside
  blind / threat-model / CVE-seeded. Runs every static-analysis engine with its
  DEFAULT rules out of the box (OpenGrep + upstream rule packs, clippy with all
  groups, dylint, cargo-audit, cargo-geiger, ast-grep enumerators) inside the
  vuln-pipeline-sast container, filters and clusters the output into CELLS,
  and hands them to the existing /triage skill for adversarial verification
  before any agent looks for real candidates. Emits SAST-FINDINGS.json (one
  candidate per cell, every site listed) plus PRUNE-LEDGER.md
  — the per-rule yield table that decides which rules to keep. Use when asked to
  "run sast", "sast-driven pass", "run the scanners on <crate>", or to score the
  rule packs across several crates.
argument-hint: "<crate-name> [--commit <sha>] [--results <dir>] [--remote tamm] [--engines a,b,c]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Task
  - Bash(docker:*)
  - Bash(ssh:*)
  - Bash(scp:*)
  - Bash(rg:*)
  - Bash(grep:*)
  - Bash(ls:*)
  - Bash(wc:*)
  - Bash(head:*)
  - Bash(jq:*)
  - Bash(python3:*)
---

# /sast-driven

The fourth find mode. Everything the other three modes do is *reasoning from source*; this one is
**tool-first**: run every scanner at full default breadth, then spend the reasoning budget on
**filtering** rather than on searching.

**Why it is a separate mode and not a stage inside the others.** Two reasons, both about keeping the
measurement clean:

1. **No contamination.** If SAST hints were injected into the blind pass, the blind pass's unique-find
   rate — the thing that justifies it existing — becomes unmeasurable. The modes stay separate so
   "what did SAST find that the other three didn't?" has an answer.
2. **Different failure mode.** The other passes fail by *missing* things. This one fails by
   *drowning* you. It therefore needs its own budget discipline (cells, not hits) and its own
   success metric (yield per rule), neither of which belongs in the other passes.

**v1 premise: take every default rule, prune from measured yield.** Do not hand-pick rules up front —
that just moves the guesswork earlier. Run everything, record what each rule produced, and prune the
rules that never pay across several crates. `PRUNE-LEDGER.md` is that record and is the mode's most
valuable output in the first few runs — more valuable than its findings.

---

## Step 0 — Where does it run

The container is `vuln-pipeline-sast:v1` (built from `docker/sast/Dockerfile`). Heavy compiles and
the whole engine matrix belong on a remote build box, not a laptop — run them over SSH on a host you
control:

```bash
# one crate (remote — the default for real runs)
ssh <remote-host> 'cd ~/rip-sast && SAST_IMAGE=vuln-pipeline-sast:v1.3 \
  ./sast-scan.sh h2 https://github.com/hyperium/h2 <commit>'

# the whole corpus + the cross-crate yield table
ssh <remote-host> 'cd ~/rip-sast && SAST_IMAGE=vuln-pipeline-sast:v1.3 \
  ./run-batch.sh ~/rip-sast/pins.jsonl ~/rip-sast/results [name ...]'
```

Results land in `~/rip-sast/results/<crate>/<timestamp>/`. Use the highest `v1.N` tag — the base image
is expensive to rebuild, so script fixes ship as thin overlays.

`sast-scan.sh` is two-phase and the split is the security contract: **fetch** runs with network but
executes nothing (`cargo fetch` resolves and downloads; no `build.rs` runs), **analyze** runs with
`--network none` and is where clippy/dylint compile the crate and therefore *do* execute its build
scripts. Never invert that. If the host has no gVisor the script says so out loud and records
`sandbox: docker-default` in the manifest — read that field before trusting a run on a new host.

If `--results <dir>` names an existing run, skip to Step 1.

---

## Step 1 — Read the run manifest FIRST, before any finding

Open `manifest.json` and `summary.json`. Report, in this order:

1. **Which engines actually ran** — `engines_ok`, `engines_absent`, `engines_failed`. An absent
   engine is a *hole in coverage*, not a clean result. Say which classes went uncovered because of
   it. Never present a summary as complete when an engine failed.
2. **`parse_errors`** — a normalizer that could not read an artifact silently loses that engine's
   entire output. Treat a non-empty list as a failed run for that engine.
3. **The volume**: `raw_hits → kept_hits`, `dropped` by reason, `hits_per_kloc`, `cells`.
4. **`sandbox`** and `image_digest` — the run is only comparable to other runs with the same digest.

If `cells` > 40, stop and say so: the filter chain is not carrying its weight on this target and
triaging 40+ cells by agent is the expensive failure mode this design exists to avoid. Tighten the
structural filter or narrow the rule packs before continuing.

---

## Step 2 — Capability gate (free, no agents)

Read the target's `THREAT_MODEL.md` §9 / `capabilities.json` if present. Drop cells whose class the
target provably lacks — no `inbound_c_abi` → drop FFI cells; no `concurrency_async` → drop the
concurrency cells; no `unsafe` in the crate → drop unsafe-soundness cells.

**Record every drop with the capability evidence that justified it.** A skip with a paper trail is a
decision; a skip without one is an oversight.

---

## Step 3 — Hand the cells to `/triage` (NOT a bespoke judge)

`normalize.py` writes **`SAST-FINDINGS.json`** directly: one candidate per cell, every site listed,
rules ordered rarest-first. Run the proven triage on it:

```
/triage <results-dir>/SAST-FINDINGS.json --repo <src> --fp-rules profiles/rust/fp-rules.txt
```

`/triage` already does the four jobs this stage needs — **verify** each candidate is real (adversarial
N-vote), **dedupe** across runs and scanners, **rank** by *derived* exploitability rather than the
scanner's claim, and **route** — and it is battle-tested, checkpointed, and resumable.

> **The bespoke reachability judge that used to sit here was removed on measurement, not taste.**
> Scored against ground truth for the first time in an internal experiment (E9): 4 crates with
> known fix sites, 29 cells, 29 blind agents → **27 `yes`, 2 `no`, 0 `unknown`. A 7 % prune rate.**
> Recall was 5/5 on the cells containing the real defect, but trivially so — a gate that passes 93 %
> of everything is not a gate. The reason is structural: *"can attacker input reach this class of site
> in this module"* has a predetermined answer on a crate whose entire public surface consumes
> untrusted bytes. Both `no`s were refutations of the rule's CLASS, not of reachability.
>
> The pass was not worthless — it was the only stage that ever **read what the pipeline produced**,
> and it found three defects upstream of itself (`unwrap_or*` mis-classified as `panic-surface`;
> in-file `#[cfg(test)]` code reaching agents; serialize-side merged with parse-side). All three are
> fixed. That is a code-review result, not a per-run gate, and it should not be paid for on every run.

**Do NOT re-sample the evidence.** Cells carry **every** site, grouped by rule. The 8-exemplar cap
that used to sit in `normalize.py` had no cost justification (median cell = 10 hits; the largest in
the E9 set = 337 ≈ 2.7k tokens, against a median **54k tokens** each judge already spent reading
source) and it did real harm: the pack located the true defect site in **7 of 8** crates, but the site
was among the 8 shown in only **2 of 8**. Removing the cap alone took that to **7 of 8**.

> **Ranking still matters, and it is not by hit count.** Rank cells — and sites within a cell — by the
> RARITY of the rule that produced them. Two independent measurements agree: E7c (a rule's hits/crate
> runs inversely to its discrimination rate — 1.9/crate → 11.1 %, 32.5/crate → 0.5 %) and the h2 pass
> (the two *smallest* cells produced both real seeds; the five largest, 527 hits combined, produced
> none). A rule that fires everywhere in a mature crate is usually guarded everywhere.

`SAST-FINDINGS.json` carries `scanner_confidence` = inverse rarest-rule count, which `/triage` uses as
a **scheduling prior only** — it never affects a verdict.

---

## Step 4 — Find, on the cells `/triage` did not refute

For each cell `/triage` kept (its `verdict` is not `false_positive`), spawn one finder subagent. The brief is the standard review brief from `/vuln-scan` **plus** the cell
as *additive* context:

```
… standard review brief …

ADDITIONAL CONTEXT (additive — attend to this, do NOT restrict yourself to it):
Static analysis clustered {hits} hits of class {class} in {module}. Rules that fired: {rules}.
ALL sites the rules hit, rarest rule first: {sites_by_rule}. `/triage` verdict and rationale: {triage}.

These are TOOL OUTPUT, not findings. Most are noise. Your job is to read the actual code and decide
whether any of them — or anything else you notice while reading — is a real, attacker-reachable
defect. A hit you cannot justify from the source is not a finding, no matter how many rules fired.
```

The "additive, not restrictive" phrasing is not decoration: a finder told to look *only* where the
rules point loses exactly the unexpected-class recall the blind pass exists to provide.

Output findings in the standard `F-NNN` shape (same as `/vuln-scan`).

---

## Step 5 — Write the two artifacts

**`SAST-FINDINGS.json`** — the `/triage` ingest shape, identical to `/vuln-scan`'s, plus per-finding
provenance:

```json
{"id": "F-001", "file": "...", "line": 0, "category": "...", "severity": "...", "confidence": 0.0,
 "title": "...", "description": "...", "exploit_scenario": "...", "recommendation": "...",
 "provenance": {"mode": "sast-driven", "cell_id": "...", "rules": ["clippy::indexing_slicing"],
                "engines": ["clippy", "opengrep-semgrep-rust"], "triage_verdict": "..."}}
```

**`PRUNE-LEDGER.md`** — the yield table. **This is the point of the first several runs.** One row per
rule that fired:

| rule | engine | group | hits | cells | hits/crate | survived cap-gate | survived triage | candidates | confirmed |
|---|---|---|---|---|---|---|---|---|

Plus the roll-ups that actually drive decisions: **by clippy group** (is `pedantic` earning its
noise? is `nursery`?), **by rule pack** (semgrep-rust vs trailofbits vs our own), and **by engine**.

> **Auditing the classifier: a rule is named for its REMEDY, not its TRIGGER.** Read what makes a
> rule *fire*, never what it asks you to do about it. Both directions of this error were caught on
> the first pass:
> - `clippy::missing_panics_doc` reads as documentation — it fires because clippy **proved the
>   function can panic**. It is a panic-surface detector. Nearly demoted by mistake.
> - `clippy::checked_conversions` reads as a missing check — it fires where a manual check **already
>   exists** and asks you to spell it differently. Its firing is evidence the guard is *present*.
>   Nearly kept by mistake.
>
> Same trap for `missing_safety_doc` (fires on `unsafe fn`), `implicit_hasher` (HashDoS), and dylint's
> `non_local_effect_before_unhandled_error` (state mutated before an error return — the
> broken-invariant class, and the rule that produced h2's best lead).

Prune verdicts, applied only across **≥3 crates** — one crate is not evidence:

- `drop` — fired ≳50 times, produced 0 candidates, on every crate so far.
- `demote` — produces candidates but at a bad ratio: keep it running, exclude it from cell formation
  (it can still corroborate a cell another rule opened).
- `keep` — produced ≥1 candidate that survived verify.
- `undecided` — too few firings to judge. Most rules will sit here after one crate; say so rather
  than pruning on noise.

---

## Step 6 — Hand back

1. Engines that ran / were absent / failed — **coverage holes first**, before any finding.
2. Volume: raw → kept → cells → triaged → candidates, with the drop reasons.
3. Findings, if any, top-3 by confidence.
4. The prune ledger's headline: which groups/packs are and are not paying.
5. `/triage`'s ranked survivors — that IS the candidate list; nothing else claims one.

**Then the comparison that justifies the mode** — once the same crate has been through the other
passes, report the three-way split: found by SAST only, by the other passes only, by both. That
number is what decides whether this mode stays in the rotation. Report it honestly including the case
where it is zero.

---

## Constraints

- **A tool hit is never a finding.** Nothing may go from `hits.jsonl` to `SAST-FINDINGS.json` without
  a finder agent reading the actual source and a `/triage` verdict that survived its votes. The engines' own severities
  are advisory and frequently wrong.
- **Cells, not hits, reach agents.** One agent per cell. Never fan out per hit — that is how a
  500-hit crate turns into a 500-agent bill.
- **Every drop is counted**, at every tier, in the artifact. No silent truncation.
- **Do not feed cells into the blind/tm/cve passes.** That contamination destroys the A/B this mode
  is measured by.
- **Absent engine ≠ clean.** Report holes as holes.
- Static candidates only — execution-verified crashes still come from `vuln-pipeline run`.

## Relationship to the rest of the pipeline

Backlog: `IMPROVEMENTS.md` **W28–W32**. `/vuln-scan` is the quick single-pass review,
`/variant-scan` is the three-pass recall engine, and this is the tool-first fourth mode. All four feed
`/triage`. The rule-distillation loop (a finding → a rule → retro-scan over the corpus) is **W30** and
is not built yet — until it is, `PRUNE-LEDGER.md` is maintained by hand.
