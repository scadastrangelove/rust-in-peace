# Variant analysis — "bugs travel in packs" (design note, prototype stage)

> Status: **prototyping on quick-xml** (2026-07-19). Not yet a shipped stage. This note captures the design
> before formalizing it as a principle (candidate **P7**) + a `feedback.py` edge + a skill. Per P1
> (verify-before-you-believe / L19 don't-manufacture) we prove it on a real target first, then formalize.

## The gap it closes

The harness already has **defensive** variant hunting bolted onto the *patch* side:
`patch_prompt.py` step 3 ("grep sibling call sites with the same pattern; your diff must cover all of
them") + the `<variants_checked>` field, and the patched-crate re-find ("the patch may have fixed one
caller, not another"). There is **no offensive variant analysis** on the *find* side — nothing takes a
lead and sweeps the codebase for the same pattern as **new** candidates. `feedback.py` has edges for
find-continue (union-of-N dry-up) and triage→fuzz-confirm (CONTESTED), but **no `candidate → variant sweep`
edge.** Real bug-hunting lore ("баги ходят косяками" / Project Zero variant analysis) is the offensive
version and it is the higher-ROI direction — a recall multiplier.

## Core design (with the key refinement)

**The seed is a PATTERN, not a finding — and it comes from ANY candidate, not only CONFIRMED ones.**

The naive version ("a confirmed bug → sweep its siblings") is too narrow. Control coverage of a pattern is
**non-uniform across its instances**: the same dangerous shape is guarded in one place and unguarded in
another. So:

- A **refuted** candidate is not a dead end — it is a *proof that a control is needed here* plus a **seed**
  to hunt the instances where that control is missing. Refuted-here ≠ safe-everywhere.
- Therefore: extract a **pattern signature** from *every* candidate whose mechanism is security-relevant —
  `confirmed`, `contested`, **and `refuted`** — dedup to **distinct patterns**, and sweep each pattern for
  its **control-coverage map**. The finding is the **control asymmetry**: the instance where the guard the
  other instances have is absent.

| step | what |
|---|---|
| seed | pattern signature (sink shape + entry class + the guard that ought to be present) extracted from **any** candidate disposition |
| dedup | by **pattern**, not by finding — N raw candidates collapse to a few distinct patterns (cheaper, not more expensive) |
| sweep | enumerate **all instances** of the pattern (grep-cheap) + map each instance's control coverage |
| finding | the **asymmetry** — an attacker-reachable instance missing the control its siblings have |
| gate | the shared skeptic panel + `distinct_from_seed` + reachability; the seed site itself is never re-reported |

The refute-driven seed is often the *better* seed: it hands you a worked example of the correct guard
(what "controlled" looks like) to diff every sibling against.

### Third seed source: the project's own historical CVEs / RUSTSEC advisories

Seeds come from **three** sources, not two: (a) our confirmed findings, (b) our refuted findings, and
(c) the **project's historical security fixes** — RUSTSEC / GHSA / CVE + the **fix commit**. Source (c) is
arguably the **highest-grade** seed: a published advisory is a curated, real, community-verified pattern,
and its fix commit pins the *exact control that was added* — the precise reference to diff every sibling
against ("does commit X's guard cover every instance of the pattern, or only the one the reporter hit?").
This is the classic 1-day→variant / patch-gap pipeline (Project Zero mines the patch and finds the variants
it missed).

**Evidence this is not hypothetical — the CVE history of our three targets already contains the pattern:**

| advisory | pattern | our finding = its variant |
|---|---|---|
| **RUSTSEC-2026-0195** (quick-xml #970) — unbounded namespace-declaration alloc (COUNT) | `NamespaceResolver::push` per-decl alloc, no cap | **our #977** = the **DEPTH** sibling in the *same function* (u16 `nesting_level`). Seeding from 0195 reaches #977 by method. |
| **RUSTSEC-2026-0187** (lopdf #502) — stack overflow via deeply nested arrays, parser recursion; fixed 0.42.0 by `MAX_NESTING_DEPTH` | recursion following untrusted structure depth, no cap | **our L13** (PageTreeIter cap) = the same pattern at a *different site* (page tree vs parser). Two fixes, two sites, one pattern. |
| **RUSTSEC-2026-0194** (quick-xml #969) — O(N²) duplicate-attribute check | quadratic work from a parsed count | a pattern **none of our lenses covered** — the CVE *adds* a class (quadratic-from-count). |

The lopdf case is the sharpest control-coverage setup we've seen: master (0.44.0) now carries **two** named
depth controls — `PAGE_TREE_DEPTH_LIMIT = 256` (page tree) and `MAX_NESTING_DEPTH` (parser, the 0187 fix,
threaded through `_direct_object`/`array`/`inner_dictionary`). The precise sweep question is: *is there any
recursive descent that uses **neither**?* (outlines / bookmarks / destinations / content-resource
resolution). Two proven guards to diff every recursion against.

**Design update:** the variant stage enumerates seeds from all three sources; for a CVE seed it fetches the
advisory + the fix commit and uses the fix's guard as the coverage reference. Net-new pattern the CVEs
surfaced that our finding-seeded lenses missed: **quadratic-complexity-from-a-parsed-count** (quick-xml
0194) — add it to the standard lens set.

## Proof from the quick-xml prototype

Two independent instances of the refinement, both already in our own data:

1. **The refuted-would-have-been-the-seed case (counter overflow pattern).** The confirmed bug was
   `NamespaceResolver::push`'s unguarded `nesting_level += 1` on a **u16** (overflow at 65 536 ≈ 200 KB —
   reachable). The pattern's other instances — `reader/mod.rs` `read_to_end` `depth` and `de/mod.rs` skip
   `depth` — are `i32` (overflow at 2³¹ ≈ 6 GB — not reachable) and `name.rs count` is `usize` + capped
   (#970). Had the finder hit an `i32` instance first and had it **refuted** (correctly, on reachability),
   a confirmed-only rule would have dropped the whole pattern and **never reached the reachable u16**.
   Pattern-seeding reaches it; finding-seeding does not.

2. **The control-asymmetry case (duplicate-binding).** Run B **refuted** "duplicate attribute" as *guarded*
   (`check_duplicates` default `true`, `events/attributes.rs`). But `NamespaceResolver::push` iterates the
   same attributes with **`with_checks(false)`** (`name.rs:713`) — the identical pattern with the control
   **switched off** → the namespace duplicate-binding / signature-wrapping finding. We caught this by luck
   in a T5 lens, not by discipline. A control-coverage sweep seeded from the *refuted* "dup-attrs is
   guarded" candidate finds it deterministically.

## Prototype run

`scratchpad/qxml_variant.mjs` (workflow `wlmkzqcsg`): 4 pattern lenses — V1 fixed-width-counter arithmetic
(+ the guarded/unguarded sibling tell), V2 recursion/accumulation following untrusted depth, V3 parallel
entry-point twins (guard in one reader impl, missing in another), V4 copy-paste idioms — over a clean
`master` worktree, then the standard 3-skeptic refute panel with a `distinct_from_seed` gate.

**Next iteration (from the user's refinement):** add a pass seeded from the **refuted/contested** candidates
of Runs A2/B2 (dup-binding-is-guarded → where is it not; escape-unsafe-is-NOTE → any real unsafe;
each differential) framed explicitly as *control-coverage mapping*, and compare yield vs the confirmed-seeded
pass. If the refute-seeded pass finds ≥1 real asymmetry the confirmed-seeded pass missed, that is the proof
to formalize P7 + the `feedback.py` edge.
