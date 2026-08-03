---
name: sast-prioritise
description: >-
  The stage between SAST enumeration and the finder. Takes the stateful cell QUEUE
  (algorithmically pre-scored by measured priors) and spends a small agent budget deciding
  what is WORTH READING and what question to ask — never whether a bug exists, which is the
  finder's job. Writes its judgement back into the queue so the corpus is worked through
  incrementally: these cells have been looked at, these have not. Use when asked to
  "prioritise the cells", "triage-lite", "what should the finder read first", or before
  spending a finder pass on a large corpus.
argument-hint: "<queue.jsonl> [--top N] [--crate NAME] [--class CLASS] [--repo-root DIR]"
allowed-tools:
  - Read
  - Glob
  - Grep
  - Write
  - Edit
  - Task
  - Bash(python3:*)
  - Bash(jq:*)
  - Bash(wc:*)
  - Bash(ls:*)
  - Bash(rg:*)
---

# /sast-prioritise

The SAST layer enumerates; the finder reads; this stage decides **reading order**. It exists because
the two numbers on either side of it do not meet: a corpus pass produces thousands of cells, a finder
pass costs an agent call each, and without a stage in between the only lever anyone reaches for is
budget — which conflates *what is worth reading* with *what we can afford*.

**This stage never decides whether a defect exists.** It decides whether a cell deserves a finder's
attention and, more usefully, *what question* the finder should arrive with. A cell it ranks low stays
in the queue; see the discipline at the end.

---

## Step 0 — Read the queue, do not rebuild it

The queue is state, not a run artifact. `scripts/build_sast_queue.py` (re)builds it from
`cells.jsonl` and **preserves** every human/agent decision already recorded. Load it and report:

1. `cells` total, `by_status`, `by_class`, and how many carry a decision already.
2. The prior range, and the fact that priors are **priors** — measured directions, not mined rules.
3. What is NOT yet minable: until cells carry outcomes, no predictor can be fit. That is the point of
   writing decisions back.

If the queue does not exist, build it first — never prioritise from a raw `cells.jsonl`, because the
result would have nowhere to live.

---

## Step 1 — Understand the three cell families before judging any of them

They are not the same kind of object and must not be judged by one rubric. This is a correction from
measurement, not taste: the first prior blended them and put `limit-pair` cells with a SINGLE
declaration at the top of the queue, which is exactly backwards.

| family | what a cell means | what makes it worth reading |
|---|---|---|
| **rule cell** (`resource`, `index-surface`, `unsafe`, …) | N rule hits of one class in one module | RARITY. E7c: 1.9 hits/crate → 11.1 % discrimination vs 32.5 → 0.5 %. In the h2 pass the two SMALLEST cells produced both real leads; the five largest (527 hits) produced none |
| **`limit-pair`** | cap DECLARATIONS vs ENFORCEMENT sites in one module | the ASYMMETRY. object: 287 declared / 13 enforced overall, concentrated (`src/macho.rs` 51/0). A 1-declaration cell is the least interesting, not the most |
| **`coverage-gap`** | a shipped file **no rule pointed at at all** | density of LOGIC-shaped sinks (alloc / unsafe / unwrap). Not `index`/`cast`/`arith_sub`: lopdf's `glyphnames.rs` scored 3,281 of those and is a pure data table |

---

## Step 2 — Select the slice, and say what you are NOT looking at

Take the top `--top N` by `prior` among `status: unread`, honouring `--crate` / `--class` filters.
Then state, in the same breath, how many cells were left unread and at what prior — a slice that does
not name its own tail reads as a complete pass.

---

## Step 3 — One agent per cell

Spawn `subagent_type: "general-purpose"`, all in one message. The brief below is derived from
`/vuln-scan`'s review brief and `/triage`'s ranking prompt, cut down to the one judgement this stage
makes.

```
You are deciding whether a static-analysis CELL is worth a security reviewer's time, and what
question that reviewer should arrive with. You are NOT deciding whether a bug exists — do not
attempt a verdict, and do not report a finding.

You may Read/Grep the repository at {REPO_ROOT}. Do NOT execute anything.

CELL
  id:        {cell_id}
  crate:     {crate}
  class:     {class}          module: {module}      data path: {data_path or "unclassified"}
  evidence:  {hits} hits from {engines}
  rules (rarest first): {rules}
  sites:     {sites}                       ← every site, not a sample
  prior:     {prior}  from {prior_terms}   ← measured directions, NOT a mined rule

FAMILY RUBRIC — use the one that matches `class`:
  · rule cell    → is this class of operation, in THIS module, on a path that consumes untrusted
                   input? A rare rule firing in a parser is worth more than a common rule anywhere.
  · limit-pair   → a cap is declared {declared}× and enforced {enforced}× here. Is there a path
                   that reaches the guarded operation WITHOUT consulting the cap? That gap is the
                   whole question; a module that declares one cap and enforces none may simply have
                   nothing to guard.
  · coverage-gap → NO rule fired anywhere in this file. Does it contain reachable logic (parsing,
                   arithmetic on parsed values, indexing, unsafe), or is it data/boilerplate?

────────────────────────────────────────────────────────────────────
STEP 1. Read enough of the module to answer: what does this code DO, and is it on a path that
sees attacker-controlled bytes? Name the entry point you traced to, or say you could not find one.

STEP 2. Assign PRIORITY, and be willing to say `low`:
    high    — reachable from untrusted input AND the cell's shape could plausibly break there
    medium  — reachable, but the shape looks guarded or the class is weak here
    low     — not attacker-reachable, or the sites are structurally uninteresting (data tables,
              generated code, pure boilerplate)
    unknown — you could not establish reachability from what you read; say what is missing

STEP 3. Write the QUESTION a finder should arrive with — one sentence, specific to this module.
"Check for bugs" is a non-answer; "does `parse_header` bound `len` before the `vec![0; len]` at
:214" is an answer.

STEP 4. State what you did NOT read, and what would change your priority.

Return JSON only:
{"cell_id": "...", "priority": "high|medium|low|unknown",
 "reachable_from": "entry point or null", "question": "...",
 "reason": "2-3 sentences", "unread": "what you did not look at"}
```

**Assume nothing from the prior.** The prior chose the reading order; it is not evidence about the
code. An agent that reproduces the prior instead of reading has done nothing.

---

## Step 4 — Write decisions back into the queue

For each judged cell set `agent_priority`, `agent_reason`, `question`, `status: "in-review"`,
`updated`, `by`. Never drop a row. Then report:

1. The priority histogram, and specifically how often the agent DISAGREED with the prior — that is
   the first evidence about whether the priors are any good, and the seed of the future mined
   predictor.
2. Cells the agent could not establish reachability for (`unknown`): a queue that hides those is
   hiding its own blind spot.
3. What remains `unread`, with the prior at the cut.

---

## Constraints

- **Priority is an ORDER, never a CUT.** A `low` cell stays in the queue with its reason recorded.
  `deprioritised` is not terminal and nothing is deleted — otherwise this stage re-creates the silent
  zero ("we never looked" reading as "there was nothing") one layer higher.
- **No verdicts.** This stage may not mark a cell `candidate` or `refuted`; only a finder pass with
  an independent PoC may.
- **Priors are priors.** They are measured directions (E7c rarity, the class × engine grid, the
  limit-pair asymmetry), not mined rules. Do not present them as learned.
- **Every judgement is written back.** An agent call whose output is not persisted converts budget
  into nothing and leaves the corpus exactly as unlabelled as before.
- **Say what was not read.** At both levels: the agent names what it skipped inside a cell, and the
  stage names the tail of the queue it never reached.
