# What our own findings can and cannot become rules — a systematic pass

**Scope:** all 19 mechanism clusters behind the 58 disclosed findings (2026-07). Clusters, not
artifacts, are the right unit: "lopdf 4× unbounded recursion" is one mechanism, four reports.

**Why this document is public while the corpus is not.** It records *mechanisms and their
expressibility* — no file, no line, no unfixed-defect location. That is exactly the split that makes
the whole approach work: the corpus stays local and gitignored, generalized knowledge ships.

**Categories.**

| | meaning | who resolves it |
|---|---|---|
| **R** — rule-able | a pattern can express the defect itself | a candidate rule, gated on DVRA-style positive/negative tests |
| **E** — enumerable | a pattern can find the *sites*, but the defect is a relation between them | an enumerator feeding the mirror-walk; judged on completeness |
| **N** — reasoning-only | no pattern expresses it; the defect is semantic | threat-model reasoning, differential harness, dynamic verification |

The previous keyword-based estimate ("55% covered") is withdrawn: it classified by title text and
**missed `miniz_oxide init_tree`, the flagship example of the very family it was derived from**,
because that title says "chained degenerate blocks" rather than "limit". Classification by mechanism
requires reading the mechanism.

> **Correction, 2026-07-29 (W34/E8).** R/E/N above is written as a property of the *class*. It is not.
> It is a property of the **(class × engine) pair**, and the grid below shows the same class landing
> in three different columns depending on the instrument. The class column in "The map" is therefore
> read as *"grade under ast-grep"*, which is what it was actually derived against — see the grid for
> the rest.

### Grade is a property of (class × ENGINE) — measured, not asserted

| mechanism | ast-grep | CodeQL | Miri | the measurement |
|---|---|---|---|---|
| self / serde re-entrant recursion | **R** | **N** | — | 6/6 vs **0/6** — re-entry crosses a caller-chosen generic, `deserialize_seq` → `<<UNRESOLVED>>`, so the call graph breaks exactly at the interesting edge |
| **mutual** recursion (A→B→A) | **N** | **R** | — | ast-grep cannot express a call graph at all; CodeQL finds real cycles (quick-xml `normalize_attr_steps ↔ normalize_attr_step`, lopdf `write_object ↔ write_array/dictionary/stream`) |
| unguarded pop | **E** | **R** | — | 41 → 15 corpus-wide with every drop verified arity-correct; fixture 4 TP + **7** FP vs 4 TP + **1** FP |
| allocation, `vec!`-shaped | **R** | **N** | — | `vec!` expands **0/285, 0/93, 0/15** — the size expression is not in the database, so no dataflow config can reach it |
| allocation, via helper/field dataflow | **E** | **R** | — | 4/4 with a source→sink path vs 1/4 source-connected; and CodeQL's per-value `BarrierGuard` lacks cls-alloc's "any unrelated cap in the same function silences everything" hole |
| counter width / type disambiguation | **N** | **R** | — | weakness #5 below is *bought*: `runpaths.join(&[b':'][..])` → `alloc/slice.rs` vs `p.join(s)` → `std/path.rs`; `self.narrow += 1` (u16) flagged, `self.wide += 1` (i32) not |
| guard **dominance** / ordering | **E** | **R** | — | weaknesses #3+#4: `not: follows:` is sibling-only and suppressed 2 of 25 guarded pops; a real CFG handles compound conditions and nesting |
| unwind / panic-safety | **N** | **N** | **R** | E6 — neither static engine models unwind edges; Miri decides it, validated TP/TN on thin-vec 0.2.15 → UB, 0.2.16 → silent |
| limit-bypass (the most common class here) | **E** | *unmeasured* | — | five clusters across five crates; the CodeQL leg has not been run for it and is not claimed |

Two things fall out of this that a class-level grade cannot say. First, **no engine dominates** — the
blind spots are properties of what each one *represents* (patterns have no types or call graph, QL has
no unexpanded macro, neither has an unwind edge), so no amount of rule work moves them; routing does.
Second, an **N is only ever N relative to the instruments in hand**: unwind-safety was reasoning-only
until Miri was wired, at which point it became the most *decisively* gradeable class of the set.

---

## The map

| # | cluster | mechanism | cls | what a rule/enumerator keys on |
|---|---|---|---|---|
| 1 | x509-parser | `ASN1Time::add` contract-violating panic | **E** | arithmetic on a public-API parameter with no checked/saturating form |
| 2 | lopdf | inline-image unwrap · `get_page_images` OOB · xref `/W` alloc-abort · pagetree stack overflow | **R** | unwrap/index on parsed data; **allocation sized by a parsed field** |
| 3 | lopdf | 4× unbounded recursion in the post-load `Document` graph walk (patch-gap on RUSTSEC-2026-0187) | **R** | self-recursion with no depth parameter — `rip-recursive-descent-no-depth-cap` |
| 4 | zune-jpeg | panic decoding crafted progressive YCCK | **E** | the *site* is an index/unwrap; reaching it needs component-count reasoning |
| 5 | object | (1) Zstd decompress size-cap **bypass** | **E** | `RIP-E010` — a cap exists; enumerate the paths that skip it |
| 5b | object | (2) exports-trie shared-subtree exponential time | **E** | `RIP-E012` — recursive walk with no visited set |
| 6 | gimli | quadratic DIE-attribute parsing via zero-byte forms | **E** | loop over a parsed count whose per-item cost can be zero |
| 7 | httparse | `allow_space_before_first_header_name` silently truncates the header block | **N** | a config flag changes parser control flow — pure logic |
| 8 | quick-xml | u16 nesting overflow | **E** | counter width decides reachability (u16 at 65 536 vs i32 at 2³¹) — **needs types** |
| 8b | quick-xml | serde `Deserializer` has no recursion cap | **R** | the recursion rule |
| 8c | quick-xml | `resolve_prefix` O(depth²) | **E** | nested scan over a depth-indexed structure |
| 9 | miniz_oxide | `init_tree` DoS — chained degenerate blocks **bypass `_with_limit`** | **E** | `RIP-E010`; the canonical limit-bypass |
| 10 | miniz_oxide | HuffDecodeOuterLoop2 wrong-dimension bounds compare · serde-feature invariant bypass · u32 truncation | **N / E** | dimension mismatch is semantic; truncation is enumerable |
| 11 | ciborium | recursion-limit bypass via newtype/Option wrappers | **E** | `RIP-E010` — the limit exists, wrappers route around it |
| 12 | ciborium | `Segment::pull` infinite loop on a 0–3 byte scratch buffer | **R** | `rip-loop-without-progress-guard` |
| 13 | ciborium | Serializer/CanonicalValue unbounded recursion + quadratic cost | **R** | the recursion rule |
| 14 | rmp-serde | recursion-guard gaps (newtype / empty buffer) | **R** | the recursion rule |
| 14b | ttf-parser | CFF2 BLEND unguarded pop | **R** | `rip-stack-pop-without-emptiness-check` |
| 14c | ttf-parser | avar i16 overflow | **E** | counter width — needs types |
| 14d | ttf-parser | glyf/gvar + COLR shared-subtree blowup (13 600× / 175 000×) | **E** | `RIP-E012` |
| 15 | png | zTXt/iTXt decompression bomb · Huffman rebuild · PLTE-length panic | **R / E** | index on a parsed length (R); ratio cap (E) |
| 16 | png | APNG interlaced stride · chunk-ordering · `parse_iccp` error-swallow | **N / R** | geometry and ordering are semantic; `Err(_) => {}` is matchable |
| 17 | fdeflate | Huffman-table-rebuild DoS (~15.5× vs real-data baseline) | **E** | same shape as #9 |
| 18 | image | AVIF **decode-before-limits** · WebP zero-limits animation | **E** | **ordering**: enumerate limit application vs decode call sites and compare |
| 19 | image | AVIF alpha-plane silent corruption | **N** | wrong output, no crash — needs a differential oracle |

---

## Totals, and what they mean

| class | clusters | share |
|---|---|---|
| **R** rule-able | 8 | 42 % |
| **E** enumerable | 11 | 58 % |
| **N** reasoning-only | 5 | 26 % |

(Clusters carrying two mechanisms are counted in both, so the shares exceed 100 %.)

**Enumerable dominates.** That is the same verdict DVRA's oracle reaches independently — it marks 14
of 22 findings static-invisible, with reasons of exactly this shape ("the WRONG BOUND is the bug",
"needs reasoning about two normalizers"). Two unrelated labelled corpora agreeing that most real
defects are relations rather than shapes is the strongest evidence we have that **U1 enumeration, not
U2 matching, is where a static layer pays** — which is what `docs/sast-layer.md` §2 argued from
theory and what the h2 judge pass showed in practice.

**The single most common mechanism is limit-bypass** (#5, #9, #11, #17, #18 — five clusters, five
crates: object, miniz_oxide, ciborium, fdeflate, image). A cap exists; some input shape reaches the
path that ignores it. No individual line is wrong, so no rule can flag it — but both halves are
enumerable, and the comparison is precisely the mirror walk. `RIP-E010` exists for this and is the
highest-value enumerator we have.

**The N set is a boundary, not a backlog.** httparse's config-flag truncation, image's silent alpha
corruption, png's chunk-ordering, miniz's wrong-dimension comparison — these are semantic. Writing
rules for them yields rules for "parsing", i.e. noise. They belong to the threat-model pass and the
differential harness, and recording them here stops a future round from trying.

---

## Coverage of the R set by rules that exist today

| cluster | rule | status |
|---|---|---|
| 3, 8b, 13, 14 recursion | `rip-recursive-descent-no-depth-cap` | ✅ written, fires on lopdf ×5, quick-xml ×5, ciborium ×1 |
| 12 degenerate loop | `rip-loop-without-progress-guard` | ✅ written, fires on ciborium ×13 |
| 14b unguarded pop | `rip-stack-pop-without-emptiness-check` | ✅ written, fires on quick-xml ×1, h2 ×1 — **but 0 on ttf-parser, the crate the rule was derived from** |
| 2, 15 alloc/index from a parsed field | — | ❌ **missing**. The DVRA-derived `rip-alloc-sized-by-request-uncapped` requires `req.header(..)`, so it is structurally blind to parsers. A parser-shaped sibling is the clearest gap. |
| 16 error-swallow | — | ❌ missing (`Err(_) => {}`, `let _ =` on a fallible parse) |

**The ttf-parser zero was diagnosed and fixed — in two steps, each exposing a different systematic
weakness.** See §"Systematic weaknesses" below; the rule now matches the CFF2 BLEND site
(`cff2.rs:383`) it was derived from.

---

## Measured volume, after the pop rule was corrected

Candidate rules (the ones that cost triage), 12 crates, dev/test paths excluded:

| crate | recursion | loop | pop | **candidates** | E010 limits | E012 no-visit |
|---|---|---|---|---|---|---|
| ttf-parser | 1 | 1 | 34 | **36** | 18 | 5 |
| rustls | 14 | 6 | 9 | **29** | 18 | 14 |
| quick-xml | 5 | 4 | 17 | **26** | 2 | 5 |
| ciborium | 1 | 13 | 0 | **14** | 0 | 1 |
| object | 0 | 10 | 3 | **13** | 2 | 1 |
| lopdf | 5 | 1 | 2 | **8** | 14 | 5 |
| image | 1 | 5 | 0 | **6** | 13 | 1 |
| h2 | 1 | 0 | 2 | **3** | 6 | 1 |
| image-png | 2 | 0 | 0 | **2** | 4 | 2 |
| httparse | 0 | 2 | 0 | **2** | 4 | 0 |
| miniz_oxide | 0 | 0 | 0 | **0** | 16 | 0 |
| hyper | 0 | 0 | 0 | **0** | 16 | 0 |

~139 candidates across 12 crates — triageable, and concentrated where the corresponding findings
actually were (lopdf/quick-xml recursion, ciborium loops, ttf-parser pops). The enumerators are
larger by design: 113 limit APIs and 35 unguarded recursive walks are *worklists* for the mirror
walk, judged on completeness.

**Do not read the two zeros as clean.** miniz_oxide and hyper score 0 candidates because their
defects are limit-bypass and protocol logic respectively — E010 correctly surfaces 16 limit APIs in
each. Absence of candidate hits on a crate whose findings are class **E** or **N** is the expected
result, not a miss.

---

## Systematic weaknesses — found by measurement, recorded rather than tuned away

Six distinct failure modes surfaced while building five rules. They are listed because each is
*generic to syntactic rule-writing*, not specific to these rules.

**1. Idiom-encoding: the rule captures one library's spelling, not the mechanism.**
The pop rule required `.pop().unwrap()` — the std `Vec` idiom — and scored **0 on the crate it was
derived from**, because ttf-parser's `ArgumentsStack::pop()` returns a value directly:
`let x1 = self.x + self.stack.pop();`. An infallible-by-signature `pop()` is the *more* dangerous
shape: on an empty stack it yields a default silently, with no `unwrap` for a reviewer or a rule to
notice. Same species: assuming `Command::new` with a literal program is safe, which lost
`Command::new("sh")`.
*Test for it:* run every rule against the crate its finding came from. That is the one check that
cannot be skipped.

**2. No fall-through between structurally identical `any:` branches.**
*(Corrected 2026-07-28 — the first diagnosis, "constraint bleed", was wrong and is withdrawn. A
sibling agent challenged it and a direct probe disproved it: on ast-grep 0.45.0 an unsatisfiable
constraint on one branch's metavariable does NOT veto another branch.)*
The real mechanism, established by probe: within one rule's `any:`, **the first branch that matches
STRUCTURALLY claims the node; if its constraint then fails, the node is discarded rather than retried
against the next branch.** Two branches both spelled `Command::new($X)` therefore collapse to
whichever came first — the computed-program shape stopped firing entirely while the rule still looked
healthy. Split into separate rules and both fire.
*Rule:* one shape per rule — the remedy was right even though the diagnosis was not.

**3. Order-blindness: "a guard exists" ≠ "a guard dominates".**
The corrected pop rule still missed CFF2 BLEND, because the function *does* contain
`if p.stack.len() < len` — just **after** the unguarded pop that is the actual defect. Presence-based
guard detection suppresses exactly the findings where the guard arrived too late. This is `fp-rules`
R1 restated ("show the invariant dominates the read on every path") and it is the single most
important limit of `inside/has` reasoning.
*Partial fix:* `not: follows:` gives statement ordering, and with it the rule matches `cff2.rs:383`.

**4. Nesting-blindness of `follows`.**
`follows` is sibling-based. A pop nested inside two `for` loops cannot see a guard that precedes the
loops, so genuinely guarded pops still fire (ttf-parser `cff2.rs:395`). Ordering is now approximate
in one direction rather than absent — a real improvement, not a solution. Proper dominance needs a
CFG.

**5. Type-blindness.**
`slice::join` and `Path::join` share a name (`object`'s `runpaths.join(&[b':'][..])`); a `u16`
counter overflows at 65 536 while its `i32` sibling never does; Axum's `Path<u64>` extractor *is* the
traversal guard. None of this is visible to a syntactic engine. This is why DVRA's oracle marks
`unsafe impl Send` static-invisible — "the WRONG BOUND is the bug" — and why Dylint (HIR + types)
exists in the tool tiering.

**6. Shape inheritance from the development corpus.**
Rules developed on DVRA are web-application shaped and scored **0 across 12 real crates** — not
precision, *zero coverage*: those six parser crates hold 35 `with_capacity` sites and no `req.*`
accessor at all. A rule inherits the shape of the corpus it was written against. Develop against the
shape you intend to hunt.

**Process defect, three occurrences in one session:** suppressing a tool's stderr (`2>/dev/null`) and
reading empty output as "no matches". A YAML parse error (`pattern: const $L: $T = $V` — YAML sees a
nested mapping) killed an entire rule file, and every crate reported 0. This is `LESSONS.md` L52 —
a status that describes the wrong thing — arriving through a third channel.
*Rules:* never discard stderr on a measurement path; validate rule YAML locally
(`yaml.safe_load_all`) before shipping it to a container.

### Three of these six are now *bought*, not fixed — by a second engine

Weaknesses 3 (guard dominance), 4 (nesting-blindness) and 5 (type-blindness) are the ones the list
calls unsolvable without a CFG or types. A CodeQL port of the same classes
(`rules/codeql/rust/`, measured 2026-07-28, full A/B in `docs/sast-layer.md` §10.1) resolves exactly
those three and no others:

| weakness | status with CodeQL | measured |
|---|---|---|
| 3 + 4 · dominance & nesting | **resolved** — real CFG | unguarded-pop 41 → **15** corpus-wide, every drop verified arity-correct, incl. the compound-condition guards this file lists as "cannot see"; fixture FPs 7 → 1 at equal recall |
| 5 · types | **resolved** | `runpaths.join(&[b':'][..])` → `alloc/src/slice.rs`, control `p.join(s)` → `std/src/path.rs`; `self.narrow += 1` (u16) flagged, `self.wide += 1` (i32) not |
| 1 · idiom-encoding | unchanged | a QL query encodes an idiom just as easily |
| 2 · `any:` fall-through | n/a | engine-specific to ast-grep |
| 6 · corpus shape | unchanged | a property of the *corpus*, not the engine |

And the reverse direction, which is why this is routing rather than replacement: CodeQL scores
**0/6 on serde re-entrancy** (re-entry crosses a caller-chosen generic — `deserialize_seq` resolves
to `<<UNRESOLVED>>`, so the call graph breaks at precisely the interesting edge) and **cannot see any
`vec!`-shaped allocation at all**, because `vec!` expands 0 times out of 285 / 93 / 15 in the three
databases built. The lopdf allocation site that is our own ground truth is unreachable by any
dataflow config there, and ast-grep holds it.

So: **ast-grep authoritative for serde recursion and `vec!` allocation; CodeQL authoritative for
mutual recursion, pop dominance, and type disambiguation.** Neither is a superset. Read §10.1 before
trusting a zero from either.

---

## Ground truth: recovered from the fix PRs, not blocked by embargo

An earlier version of this document claimed site recovery was blocked by embargo. **There is no such
constraint, and the whole framing was a self-inflicted invention.** Embargo restricts *publication*;
nothing here is published. The corpus is build-local working data, and what ships is a generalized
rule that names no crate, no file and no line — so a defect reported through a private advisory is
exactly as usable a rule source as one reported through a public PR. The `embargo_risk` field has
been removed from the tooling rather than corrected.

`scripts/fetch_fix_regions.py` recovers locations from the fix diffs — a *better* source than any
prose citation, because the fix is authoritative and, per `variant-analysis.md`, "pins the exact
control that was added".

**Result: 26 fix PRs, 172 hunks, 15 crates** — every finding filed as a PR, regardless of channel. Recorded as `granularity: "fix-hunk"` — a region the
fix touched, not the defect line, since a fix PR also carries scaffolding, new API, docs and tests.

## Verification: rules land in the files our fixes touched

| crate | candidate hits | in a fix-touched file | files hit |
|---|---|---|---|
| httparse | 2 | **2 (100 %)** | `lib.rs` |
| image | 6 | 4 (66 %) | `decoder.rs` |
| quick-xml | 26 | 13 (50 %) | `map.rs`, `mod.rs`, `name.rs` |
| lopdf | 8 | 4 (50 %) | `destinations.rs`, `document.rs`, `parser_aux.rs` |
| ttf-parser | 36 | 7 (19 %) | **`cff2.rs`, `colr.rs`, `gvar.rs`** — all three |
| object | 13 | 1 (7 %) | **`exports_trie.rs`** |
| image-png | 2 | 1 (50 %) | `mod.rs` |

The hits are specific, not diffuse: `cff2.rs` is the CFF2 BLEND finding, `exports_trie.rs` the
shared-subtree blowup, `document.rs` the lopdf recursion cluster.

**The three zeros each mean something different, and only one is a miss-shaped result:**

- **miniz_oxide (0 candidate hits)** — its finding is class **E** (limit-bypass). E010 surfaces 16
  limit APIs there. Correct behaviour, not a gap.
- **h2 (3 hits, 0 in fix files)** — the fix was `proto/streams/send.rs`; the finding is class **N**
  (RFC §8.2.2 conformance). Correct.
- **ciborium (14 hits, 0 in fix files)** — **an artefact of the measurement**: ciborium's findings
  were filed as advisories rather than PRs, so no fix diff has been harvested for them yet and there
  is no ground-truth row to compare against. Zero here means "nothing to compare against", not "the
  rule missed". Our own fix branch for the encode-recursion finding exists and is the obvious next
  source.

**⚠ File-level co-location turned out NOT to be evidence of recall — proven, not suspected.**

The table above showed the recursion rule hitting 4 of 8 lopdf sites in fix-touched files, and that
was read as support. A per-class agent then measured the same rule against the actual defect sites
and scored it **0 / 6**. The cause is structural: `pattern: $FN($$$ARGS)` binds only a *bare-identifier
callee* in tree-sitter, so `self.walk(..)` — the dominant Rust recursion idiom and the shape of every
lopdf finding — never matched at all. The rule was hitting the right files for entirely unrelated
reasons.

So the honest reading of the co-location table is: it is a **weak necessary condition**, not
evidence. A rule can land in the right file and still be blind to the mechanism that file was fixed
for. Only a check against the defect site itself counts, and the classes that now have one got it
from the per-class agents, not from this table.

The original caveat still stands too: the diff line numbers are post-fix while the clones sit at HEAD
with merged fixes applied, so pre-fix reconstruction (via `gh pr diff`, as the alloc agent did for
lopdf) is what a line-level check actually requires.

## What "covered" honestly means now

| | |
|---|---|
| mechanism clusters classified | **19 / 19** |
| rule-able (**R**) clusters with a rule | 6 of 8 — missing: alloc/index-from-parsed-field, error-swallow |
| findings with recovered ground truth | **26** fix PRs / 172 hunks / 15 crates |
| rule verified line-level against its own finding | **1** (ttf-parser pop → `cff2.rs:383`) |
| rules co-located with fix files | **7 crates** |
| enumerable (**E**) clusters with an enumerator | 2 of 11 — E010, E012 |
| reasoning-only (**N**) — permanent boundary | 5 |

Classification is complete; rule coverage is partial and known; verification has moved from
circumstantial to file-level, with the line-level step scoped and not yet done.
