# Mechanism effectiveness — funnel by campaign class

Source: `findings-ledger.jsonl` (119 rows, 119 unique, 0 dupes as of 2026-07-30).
Read the funnel with `python3 scripts/lens_stats.py`; this doc adds the **per-campaign-class**
split, because a single blended number mixes three populations that were verified to different
bars and must not be compared directly.

`precision = live / (live + false + other)`; **latent excluded** — a `latent-hardening` finding is
a *real* bug that simply isn't reachable in the shipping profile (build-gated overflow, a
default-off feature flag, caller-only input). That is a correct disposition, not a false positive,
so it must not count against a lens.

## The three campaign classes (do NOT blend their precision)

### 1. Reasoning passes — chromium 2026-07 (50 findings) — THE ONLY FAIR PRECISION TEST

These ran the full blind ∪ threat-model ∪ cve-seeded find + a 3-skeptic adversarial refutation
panel, so they are the only rows where `refuted` was actively produced — i.e. where precision means
something.

| lens | surfaced | live | latent | false | precision |
|---|---:|---:|---:|---:|---:|
| blind | 31 | 14 | 8 | 7 | **60%** |
| threat-model | 28 | 15 | 6 | 5 | **68%** |
| cve-seeded | 21 | 14 | 4 | 3 | **82%** |

**Ranking on a fair test: cve-seeded > threat-model > blind.** cve-seeded's precision edge is
expected — seeding from a crate's own RUSTSEC/CVE history points the finder at classes the code has
actually gotten wrong.

**SAST rule precision (measured separately, `docs/e13/E13-result.json`): 7 / 305 cells = 2.3 %** —
see class 2 below. SAST is an *enumerator*, not an oracle: high site-coverage, ~2.3% of its flagged
cells are the real bug. Its 24 ledger findings were found *in spite of* the rules, not by them.

### 2. SAST-driven — e13 (24 findings) — "found in spite of the rules", NOT found by them

**The critical correction (2026-07-30).** The ledger originally tagged all 24 e13 rows
`sast_enumerated: direct-hit`, implying the SAST rule pointed at each bug. `docs/e13/E13-result.json`
says otherwise, and it is authoritative:

| E13 bucket | count | meaning |
|---|---:|---|
| `cells` | 305 | candidate sites the SAST rules enumerated |
| `tp` | **7** | rule flagged the *actual* confirmed defect |
| `fp` | 298 | rule flagged a non-bug |
| `other_defects` | **24** | real bug found *during* the pass, but the rule did **not** point at it |

**SAST rule precision = 7 / 305 = 2.3 %.** And the artifact's `other_defects` list is exactly the
24 ledger findings — so **0 of the 24 ledger e13 rows are rule-hits; all 24 are `other_defects`**,
found by the reasoning agent working through the (mostly-FP) cells. The 7 genuine rule-hits are a
separate bucket not carried in the ledger (one, ripgrep, isn't in the ledger at all).

Per-crate proof: crates that produced ledger findings while their SAST rules scored **tp=0** —
actix-web (26 cells, 0 tp), ntex (39, 0), image/image-png (16, 0), quinn (11, 0), regex (22, 0),
serde (18, 0) — contributed **14** of the 24 findings. In those crates *no rule ever hit*, so those
14 are unambiguously "found in spite of".

**Resolution of the remaining 10 (from tp>0 crates ttf-parser, lopdf, object, gimli, msgpack-rust).**
No separate cell→finding map was needed: `E13-result.json`'s `other_defects` list is itself the
per-finding authority, and a **per-crate identity check settles it** — for every one of the 12
crates, `count(ledger e13 rows) == count(other_defects)` exactly (e.g. ttf-parser 3 == 3 while its
`tp=2` are separate; object 3 == 3 while `tp=1` is separate; lopdf 2 == 2 while `tp=1` is separate).
The `tp` findings appear **only** as counts, never in the `other_defects` list, so they cannot be
any of the 24 ledger rows. **Therefore all 24 ledger e13 rows are `other_defects` (found-alongside);
zero are rule-hits — the "10 ambiguous" resolve to `other`, no residue.** The ledger's
`sast_enumerated` is now `site-missed` on all 24, and `scripts/lens_stats.py` enforces this split
(rule-hit vs found-alongside) and refuses to print a blended SAST precision.

So this class does **not** show "100% SAST precision". The honest reading, and it matches the
README's *enumerator-not-oracle* pattern exactly: **the SAST rules are ~2.3% precise; the value of
the sast-driven mode is the bounded worklist it hands a reasoning agent, which then finds real bugs
the rules missed.** `found_by: sast-driven` on these rows means "found by the sast-driven pass", not
"found by a SAST rule" — the `sast_enumerated` field (`site-missed` on all 24) carries that.

**The 24 found-alongside, put through the refutation gauntlet (2026-07-30).** They were originally
`source-confirmed` (author read only). A first reconcile against E13's own dynamic verification fixed
5 stale labels (ntex-stvec was actually REFUTED there, gimli was under-claimed, ttfparser-capi /
object-bloom were static-not-dynamic, lopdf-predictor is build-gated). The remaining 17 `source-read`
rows were then run through 4 adversarial skeptic agents against the real latest crate sources. Result:

| | count | examples |
|---|---:|---|
| **confirmed-live** | **11** | ttf-parser extension-recursion stack-overflow · ttf-parser CFF subr amplification · actix-multipart CR-boundary hang · ntex `from_utf8_unchecked` unsound-str · object gnu-hash rewrite-path alloc · lopdf/gimli/msgpack (dynamic) |
| **latent-hardening** | **6** | regex-automata (parser `nest_limit` caps it) · serde_derive (compile-time dev code) · regex-lite (32-bit, maintainer-documented) · quinn-proto (`set_server_config(None)` caller-driven) · png adam7 (test-only helper) · lopdf-predictor (wraps in release) |
| **refuted** | **6** | ntex router `as u16` (bounds-checked downstream) · object rewrite loop (code absent in 0.39.1) · quinn GRO stride (from kernel, not wire) · image APNG (guarded in the `png` crate) · image BMP ICC (code doesn't exist) · ntex-stvec (guarded one level up) |

So the honest count is **11 real (all Low–Medium), not 24** — precision of the found-alongside set is
**11/17 = 64 %** (latent excluded), now genuinely refutation-tested. The skeptic pass again earned its
keep: **6 of 23 were refuted** (a `png` upstream guard, two pieces of code that don't exist in the
shipped version, a kernel-not-wire value, a bounds-checked truncation), and 6 more are real-but-not-
attacker-reachable. Verification depth is now `source-traced` 19 / `dynamic-poc` 4 — zero left on the
author's word.

### 3. Historical filed corpus — prior disclosures (45 findings) — SURVIVORSHIP

rmp-serde, ttf-parser, h2/hyper, lopdf, ciborium, miniz_oxide, quick-xml, object, gimli, httparse,
rustls/quinn, gitoxide, x509-parser, zune-jpeg, actix/ntex. These are the **already-filed**
findings — pre-selected for having survived to disclosure — so ~97-100% "precision" is survivorship,
not lens quality. They are the dynamic-poc-confirmed baseline (what a finished, filed finding looks
like), not a measure of raw find precision.

## Combined — E13 + Chrome (the two campaigns this session touched)

Summing the two is legitimate for **attribution** (who found what) but NOT for a single precision
number — the two ran different modes on different targets and to different verification bars.

|  | rows | live | latent | refuted |
|---|---:|---:|---:|---:|
| Chrome (reasoning) | 50 | 21 | 15 | 12 |
| E13 (sast-driven) | 24 | 24 | 0 | 0 |
| **sum** | **74** | **45** | 15 | 12 |

**Attribution of the real findings — who actually found each (after the E13 found-alongside were
put through the refutation gauntlet — 24 surfaced verified down to 11 real):**

| finder | count | note |
|---|---:|---|
| SAST **rule** hit (`tp`) | **7** | E13 only; off-ledger (separate bucket, not these rows) |
| Reasoning lenses (Chrome) | 21 | blind / threat-model / cve-seeded |
| Found *alongside* SAST cells | 11 | E13 `other_defects` — 24 surfaced, 11 survived verification (6 refuted, 6 latent) |
| **total real findings** | **39** | 32 ledger-live + 7 off-ledger rule-hits |

So across both campaigns **reasoning found 32 of 39 (82 %); SAST rules found 7 (18 %)** — while the
mechanical SAST pass burned **339 cells (305 E13 + 34 Chrome) → 7 hits = 2.1 % rule precision**. SAST's
worklist still earned its keep: it *seeded* 11 confirmed reasoning finds (the surviving E13
`other_defects`). The honest one-liner is unchanged: **SAST is a worklist generator (2.1 % of its
cells are the bug); the reasoning layer is the finder.**

Both classes are now at a comparable bar — Chrome's 21 through skeptic panels + PoCs, and E13's 11
through the same adversarial skeptic pass (4 agents, real latest sources) that refuted 6 and
downgraded 6 to latent. Chrome's own SAST enumeration (34 cells) recorded no rule-hit finding,
consistent with E13's 2.3 %.

## Whole-ledger verification depth

| depth | count | meaning |
|---|---:|---|
| dynamic-poc | 50 | a real crash/PoC reproduced against the actual code |
| source-traced | 50 | skeptic panel + independent source trace, no PoC yet |
| source-read | 19 | author source read only (the e13 bar) |

**Independently corroborated live findings (≥2 lenses):** 29. This is the ledger's headline signal —
the overlap column shows which findings ≥2 independent lenses surfaced, the strongest confidence tier.

## Reading the funnel honestly (the standing caveats)

1. **Never blend precision across the three classes.** Only class 1 is refutation-tested. Class 2 is
   untested (no skeptic pass), class 3 is survivorship (filed = pre-selected live).
2. **Latent ≠ false.** Build-gated / flag-off / caller-only findings are real; excluding them from the
   precision denominator is deliberate.
3. **A lens's credit is clean only if it ran as its own agent** (README caveat): folded blind+TM+cve
   agents list all three in `found_by`, so their split is not real. Class 1's moxcms/fontations rows
   that show 3 lenses are genuine independent corroboration; folded small-target runs are not.
4. **This session's discipline result:** of ~112 chromium-t2 skeptic-"confirmed" rows, 22 survived to
   confirmed-live after source/PoC verification; 12 refuted, 15 latent, the rest consolidated into
   root causes or refound. Three magnitude/label errors were caught before filing (exif cubic→quadratic,
   codebook div0 refuted, id3v2 dfs refuted).

## Integrity note (2026-07-30)

The ledger grew from 120 (session-start backup, all `chromium-t2`) to 119 during the session as the
historical + e13 corpora were merged in; it is currently 119 unique / 0 dupes with all session
findings intact. But the consolidation was done with read-whole-file → edit → write-whole-file scripts,
which **race** with any concurrent appender. This is exactly IMPROVEMENTS.md **W44** (auto-append the
ledger from the pipeline by construction, one row per finding, merge-not-append). Until W44 lands,
edit the ledger single-writer.
