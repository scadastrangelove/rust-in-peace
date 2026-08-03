#!/usr/bin/env python3
"""build_sast_queue.py — turn a corpus of `cells.jsonl` into a STATEFUL triage queue.

## Why a queue and not a batch

A run is a moment; a queue is a state. Every previous pass through the SAST layer produced a number
("305 cells", "3205 cells") and no record of which cells a reader actually opened — so the same work
could be redone, and no cell could ever be labelled with what came out of it. That missing link is
exactly why prioritisation rules cannot be mined today: `E13-result.json` holds per-crate aggregates,
`other_defects` holds crate+site, and neither carries a `cell_id`. Of 24 E13 findings, at most 5 are
retro-linkable, because the archived `cells.jsonl` survive for only 2 of the 12 crates involved.

So this file is the label store as much as it is a work list. `cell_id` is the join key, `status` is
the outcome, and both persist across runs.

## Priors, and what they are not

No prioritisation rule is MINED here — mining needs outcomes, and outcomes are what this queue will
start collecting. What it does instead is order by three signals that were measured on real runs, each
recorded as its OWN term so a later mined predictor can replace them individually:

  * `rarity`     — smaller cell first. E7c: a rule's hits/crate runs inversely to its discrimination
                   (1.9/crate → 11.1 %, 32.5/crate → 0.5 %). The h2 pass: the two SMALLEST cells
                   produced both real seeds; the five largest, 527 hits combined, produced none.
  * `class_engine` — the measured class × engine grid. Applied ONLY where that grid actually has a
                   measurement; everything else stays neutral rather than inventing a number.
  * `pair_gap`   — for `limit-pair` cells, declared-minus-enforced. Measured on object: 287
                   declarations against 13 enforcement sites, and the asymmetry is concentrated
                   (`src/macho.rs` 51/0) rather than uniform, so the gap itself orders.

The blend weights are DEFAULTS, not findings. They are stated in `PRIOR_WEIGHTS` and written into
every row so that a later run can recompute or overrule them without guessing what was used.

## The one rule that must not be broken

Priority is an ORDER, never a CUT. A low-priority cell stays in the queue with `status: unread`;
`deprioritised` is not a terminal state and nothing is deleted. Otherwise this layer reintroduces the
silent-zero failure one level up — "we never looked" reading as "there was nothing".
"""
from __future__ import annotations

import argparse
import collections
import datetime as _dt
import glob
import json
import os
from pathlib import Path

# Weights are an unvalidated default blend. Replace with a mined predictor once the queue has
# outcomes; until then they are recorded per row so any later analysis can undo them exactly.
PRIOR_WEIGHTS = {"rarity": 0.6, "class_engine": 0.25, "pair_gap": 0.15}

# The measured half of the class × ENGINE grid (docs/finding-class-map.md). Only classes with a real
# measurement appear; anything absent scores 0.0 and is explicitly NOT penalised for it.
#   R = the engine can express the class · E = enumerable only · N = out of reach
CLASS_ENGINE_GRADE: dict[str, float] = {
    # CodeQL is R for these and ast-grep is N or E — the classes that justify a second engine at all.
    "index-surface": 0.8,      # guard dominance (CodeQL R / ast-grep E)
    "resource": 0.8,           # alloc via helper dataflow + `vec!` macro-opaque (CodeQL R)
    "limit-pair": 1.0,         # the most common mechanism behind real findings; no line rule reaches it
    "unsafe": 0.6,             # unsafe surface: enumerable, and Miri is R where statics are N
    "panic-safety": 0.6,       # unwind safety — N under both static engines, R under Miri
    "panic-surface": 0.5,
    "error-swallow": 0.4,
    "arithmetic": 0.4,         # counter width / type disambiguation (CodeQL R)
    "conversion": 0.3,
    "concurrency": 0.3,
    # coverage-gap is not a class the grid ever graded: it means NO rule fired here at all. It is kept
    # neutral on purpose — the point of those cells is coverage, and letting them rank by their own
    # (absent) rule evidence would push them off the queue, which is the hole they exist to close.
    "coverage-gap": 0.0,
    "unclassified": 0.0,
}


def rarity_term(cell: dict) -> float:
    """Smaller cell → higher. Same shape as `scanner_confidence` in normalize.py.

    Applies to RULE cells only. The evidence behind it (E7c's density/discrimination relation, and
    the h2 pass where the two smallest cells produced both leads) is about how many times a RULE
    fired — it says nothing about the other two cell families, and applying it there is wrong:
    see `prior_for`.
    """
    return round(1.0 / (1.0 + cell.get("hits", 0)) ** 0.5, 4)


def pair_gap_term(cell: dict) -> float:
    """declared − enforced, squashed. Non-`limit-pair` cells score 0.0 (not a penalty: no signal)."""
    if cell.get("class") != "limit-pair":
        return 0.0
    gap = max(int(cell.get("gap", 0)), 0)
    return round(min(gap / 50.0, 1.0), 4)


def gap_density_term(cell: dict) -> float:
    """For `coverage-gap` cells: how much LOGIC sits in a file no rule pointed at.

    Counts only the sink kinds that imply logic (alloc / unsafe / unwrap). `index`, `cast` and
    `arith_sub` are deliberately excluded from the ranking signal — they fire on essentially any Rust
    file, and lopdf's `src/encodings/glyphnames.rs` scored 3,281 of them while being a pure data
    table. They stay in the evidence; they just do not order.
    """
    if cell.get("class") != "coverage-gap":
        return 0.0
    sites = cell.get("sites") or {}
    logic = sum(len(v) for k, v in sites.items()
                if k.rsplit(":", 1)[-1] in ("alloc", "unsafe", "unwrap"))
    return round(min(logic / 20.0, 1.0), 4)


def prior_for(cell: dict) -> tuple[float, dict]:
    """Class-CONDITIONAL prior: each cell family is ordered by the signal measured FOR that family.

    The first version of this file blended one formula across all families and produced a degenerate
    queue: the top was `limit-pair` cells with a single hit — one cap declared once, nothing enforced
    — because `rarity` rewards small cells and `limit-pair` carries the maximum class weight. That is
    exactly backwards. For a pair cell the signal is the ASYMMETRY (object: `src/macho.rs` 51 declared
    / 0 enforced), so a one-declaration cell is the *least* interesting, not the most.

    So the families are scored separately and never mixed:
      * rule cells    → rarity (validated) × class-engine reachability
      * limit-pair    → the gap, and nothing else; rarity is meaningless here
      * coverage-gap  → density of logic-shaped sinks in an unscanned file
    """
    cls = cell.get("class", "")
    ce = CLASS_ENGINE_GRADE.get(cls, 0.0)
    if cls == "limit-pair":
        terms = {"rarity": 0.0, "class_engine": ce, "pair_gap": pair_gap_term(cell),
                 "gap_density": 0.0}
        prior = 0.75 * terms["pair_gap"] + 0.25 * ce
    elif cls == "coverage-gap":
        terms = {"rarity": 0.0, "class_engine": ce, "pair_gap": 0.0,
                 "gap_density": gap_density_term(cell)}
        prior = terms["gap_density"]
    else:
        terms = {"rarity": rarity_term(cell), "class_engine": ce, "pair_gap": 0.0,
                 "gap_density": 0.0}
        prior = PRIOR_WEIGHTS["rarity"] * terms["rarity"] + PRIOR_WEIGHTS["class_engine"] * ce
    return round(prior, 4), terms


def build_row(cell: dict, crate: str, run_dir: str, now: str) -> dict:
    prior, terms = prior_for(cell)
    rules = cell.get("rules") or {}
    return {
        # ── identity: the join key that was missing everywhere before ──
        "cell_id": cell["cell_id"],
        "crate": crate,
        "class": cell.get("class"),
        "module": cell.get("module"),
        "data_path": cell.get("data_path", ""),
        # ── evidence ──
        "hits": cell.get("hits", 0),
        "engines": cell.get("engines", {}),
        "rarest_rule": (min(rules.items(), key=lambda kv: kv[1])[0] if rules else None),
        "rarest_rule_hits": (min(rules.values()) if rules else None),
        "n_rules": len(rules),
        "loc": cell.get("loc"),
        "declared": cell.get("declared"),
        "enforced": cell.get("enforced"),
        "gap": cell.get("gap"),
        # ── ordering ──
        "prior": prior,
        "prior_terms": terms,
        "prior_weights": PRIOR_WEIGHTS,
        # ── state: this is the label store ──
        "status": "unread",          # unread | in-review | candidate | confirmed | refuted | deprioritised
        "agent_priority": None,      # set by the prioritise skill
        "agent_reason": None,
        "verdict": None,             # set once a finder/triage pass has read it
        "finding_ids": [],           # ledger ids produced by this cell — the mining label
        "first_seen": now,
        "updated": None,
        "by": None,
        "run_dir": run_dir,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cells", default="/tmp/e14-full/*/*/cells.jsonl",
                    help="glob over cells.jsonl produced by normalize.py")
    ap.add_argument("--out", default="sast-queue.jsonl")
    ap.add_argument("--crate-from", type=int, default=3,
                    help="path component index holding the crate name")
    args = ap.parse_args()

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Preserve any state that already exists: a rebuild must never reset what a reader already did.
    existing: dict[str, dict] = {}
    if os.path.exists(args.out):
        for line in open(args.out):
            if line.strip():
                r = json.loads(line)
                existing[r["cell_id"]] = r

    rows, seen = [], set()
    for path in sorted(glob.glob(args.cells)):
        parts = Path(path).parts
        crate = parts[args.crate_from] if len(parts) > args.crate_from else "?"
        run_dir = str(Path(path).parent)
        for line in open(path):
            if not line.strip():
                continue
            cell = json.loads(line)
            cid = cell["cell_id"]
            if cid in seen:
                continue
            seen.add(cid)
            row = build_row(cell, crate, run_dir, now)
            if cid in existing:
                # Recompute the priors (they are derived), keep everything a human or agent decided.
                old = existing[cid]
                for k in ("status", "agent_priority", "agent_reason", "verdict",
                          "finding_ids", "first_seen", "updated", "by"):
                    row[k] = old.get(k, row[k])
            rows.append(row)

    # ── demote limit-pair cells in DEFINITIONS-ONLY modules ──────────────────────────────────────
    # Measured twice, independently, by the prioritisation stage: `object/src/macho.rs` (51 declared
    # / 0 enforced) and `object/src/pe.rs` (39 / 0) both scored at or near the top and both are
    # format-definition modules — transliterations of the Mach-O headers and of `winnt.h`, all struct
    # fields and constants, with enforcement living in `src/read/...`. For such a file "0 enforced" is
    # the CORRECT shape, not an asymmetry, so the gap metric is measuring the wrong thing.
    #
    # The discriminator that costs nothing: a definitions module produces no OTHER class of cell. If
    # the same (crate, module) has an index-surface / resource / arithmetic cell, real code lives
    # there and the gap is worth reading; if the module's only cells are limit declarations, it is a
    # header file. Demote rather than drop — L6: priority is an order, never a cut.
    by_module: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for r in rows:
        by_module[(r["crate"], str(r["module"]))].add(str(r["class"]))
    for r in rows:
        if r["class"] != "limit-pair":
            continue
        classes = by_module[(r["crate"], str(r["module"]))]
        if classes == {"limit-pair"}:
            r["definitions_only"] = True
            r["prior_terms"]["definitions_only_penalty"] = 0.2
            r["prior"] = round(r["prior"] * 0.2, 4)

    rows.sort(key=lambda r: -r["prior"])
    with open(args.out, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    st = collections.Counter(r["status"] for r in rows)
    cl = collections.Counter(r["class"] for r in rows)
    carried = sum(1 for r in rows if r["cell_id"] in existing)
    print(json.dumps({
        "queue": args.out,
        "cells": len(rows),
        "crates": len({r["crate"] for r in rows}),
        "carried_over_state": carried,
        "by_status": dict(st),
        "by_class": dict(cl.most_common(10)),
        "prior_range": [rows[-1]["prior"], rows[0]["prior"]] if rows else None,
        "weights": PRIOR_WEIGHTS,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
