# Variant analysis — empirical results (methodology summary, 2026-07-19)

Prototype of the offensive variant-analysis discipline (`variant-analysis.md`) run on three crates we
had already worked. Seeds from **three sources**: our confirmed findings, our refuted findings, and the
project's historical **CVEs/RUSTSEC + fix commits** (control-coverage reference). Every candidate was then
**empirically PoC-gated** (not trusted on panel votes) — the whole point of the exercise was to measure how
many "confirmed" variants survive contact with a compiler.

> **Scope note.** This file records the *methodological* outcome only. Where a surviving finding is not
> yet publicly filed/fixed, its per-sink specifics (crate, function, exact code path) are abstracted and
> tracked out-of-tree; they'll be folded in once the matching disclosure is public. The refuted candidates
> and the honest negative are kept in full — there is nothing to hold there.

## Infra caveat
An API outage (`ENOTFOUND`→`403`, ~15 min) killed the two CVE-v1 runs (relaunched clean as v2) and
**degraded the verify phase** of the three our-seed variant runs — so their panel dispositions
(e.g. one crate's cluster reported "9/9 confirmed, 0 refuted") are **unreliable in both directions**.
Ground truth below is the PoC / hand-verification, not the panel.

## Survived empirical verification — 7 real

| # | crate | class | seed source | PoC result | status |
|---|---|---|---|---|---|
| 1,2,7,8 | already-worked PDF crate | **4 distinct** unbounded-recursion sinks — a patch-gap on a public RUSTSEC advisory (the advisory's fix didn't cover these paths) | our recursion lesson **+** the public CVE (both, independently) | self-ref & long (200k) chains → **stack overflow, exit 134**; a 2-node cycle is correctly caught (control) | ✅ **REAL (HIGH)** · *sinks held pending disclosure* |
| 3,4 | already-worked XML crate | serde recursion **variants of an already-public open issue** (different deserialize entry points than the ones the issue names) | our prior finding, V4 lens | depth 10k → **exit 134** | ✅ **REAL (variants)** · *held* |
| 5 | already-worked XML crate | O(depth²) quadratic-CPU DoS, sibling of a public RUSTSEC advisory | the public CVE, Q1 lens | timing ×4 per 2× N (0.019→1.463 s) = **O(N²)** | ✅ **REAL (net-new, HIGH)** · *held* |

**The convergence, not the individual sinks, is the signal:** two independent seed sources — our own prior
findings **and** a public historical CVE — landed on the *same* recursion cluster in the PDF crate. That is
the strongest possible evidence the pattern is real and not a seed artifact.

## Culled by PoC — 1 honest negative (kept in full; refuted, nothing to disclose)

| # | crate | candidate | why refuted, empirically |
|---|---|---|---|
| 6 | object | `CrelIterator::size_hint` → `.collect()` unbounded alloc | **REFUTED.** `size_hint()` does return the untrusted `header>>3` (up to ~2⁶¹, verified up to `u64::MAX>>3`), asymmetric vs its 4 sibling relocation iterators (none override `size_hint`). But Rust's `Vec::extend`/`.collect()` for a non-`TrustedLen` iterator only calls `reserve(size_hint().0)` **after** the first `next()` (inside `extend_desugared`) — and `CrelIterator::next()` **zeroes `count` on the very first parse error** (out-of-data), which fires before any capacity is ever requested. Tested at count=2.3×10¹⁸ (engineered to exceed `isize::MAX` in bytes): `.collect()` returns cleanly, no panic, no alloc. The ONLY way to trigger the lie is a caller manually doing `Vec::with_capacity(it.size_hint().0)` *before* touching the iterator — confirmed that pattern alone does panic (`capacity overflow`), but it's a caller-side anti-pattern the crate itself never uses (`RelocationMap::new` — the crate's own consumer — uses a plain `for` loop). Not reportable as-is. |

## Culled (hypothesis correctly kills them)

| crate | candidate | why refuted |
|---|---|---|
| object | `VersionTable::parse` `vec![…; max_index+1]` | `max_index` is u16 → ≤64K entries; maintainer even commented the ~32K bound. Bounded. |
| object | PE `ResourceDirectoryTable` traversal | refuted by verifier; guarded. |
| quick-xml | `reader/mod.rs`/`de` `depth` counters | i32/usize default → overflow only at 2³¹ (~6 GB) — not reachable (the one reachable fixed-width counter, a u16, was the already-filed public finding). |
| quick-xml | text `unescape` entity-cap absence | text unescape is **single-pass** (no re-expansion) → no billion-laughs → cap not needed. Correct by design. |
| — | ~13 more (XML V1–V6 refuted 12, etc.) | panel + hand refutation. |

## Verdict on the hypothesis

**Decisively validated.** Seeding control-coverage from prior findings — **confirmed, refuted, AND
historical CVEs** — surfaced **7 empirically-real bugs** across three crates we had already "finished",
that fuzzing and the original campaigns missed, **plus one honest, PoC-forced negative** (CrelIterator).
Two independent seed sources (our own findings and a public CVE) converged on the **same** recursion
cluster — strongest possible signal it's real, not a seed artifact. The refuted-as-seed idea paid off
twice over: it reached real bugs AND, applied to CrelIterator, it correctly talked itself out of a
plausible-looking false positive once PoC'd.

**The most important discipline point:** the degraded panels were wrong in BOTH directions (one crate's
cluster inflated to 9/9; another's serde-enum variant deflated to "contested") — yet **empirical PoC was
ground truth every time, in both the confirming and refuting direction.** This is exactly why the pipeline
gates on PoC, not votes (L19 / the x509 two-layer over-claim). The honesty loop held twice: the first PDF
PoC (via a save/load round-trip) *failed* → isolated it (direct pub-API call) → found a malformed-input
artifact, not a false finding, then confirmed; and CrelIterator *looked* like a real
alloc-from-untrusted-count bug by every static signal (source-verified, matches the zstd/decompress-cap
pattern, asymmetric vs siblings) but the actual `.collect()` mechanics refuted it on contact with the
compiler.

*(Disclosure tracking for the held items — channels, filing state, patch status — lives out-of-tree with
the target harnesses, and lands here once each is public.)*
