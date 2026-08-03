# The static-analysis (SAST) layer — design

> **Status:** v1 built — the tool image (`docker/sast/`), the `/sast-driven` skill, and the U1
> enumerator rule packs (`rules/`) exist, and the retro-validation experiments have been run.
> Companion to [`DECISIONS.md`](DECISIONS.md) **ADR-2** (the *why*) and
> [`../IMPROVEMENTS.md`](../IMPROVEMENTS.md) **W28** (the backlog entry). Tool facts are sourced from
> an internal Rust static-analysis tooling reference
> (verification snapshot 2026-07-20); every load-bearing claim is re-checked at implementation time —
> that document's own evidence policy.

---

## 0. The one-paragraph version

Static analysis enters this pipeline in **three roles, none of which is "a scanner that finds bugs"**:
as an **enumerator** that makes the finder's site-walk exhaustive instead of sampled (U1), as a **noisy
candidate feed** that is reachability-filtered and clustered before any agent sees it (U2), and as
**signature memory** — every campaign finding is distilled into an executable rule that permanently
re-runs on every future and every *past* target (U3), with refuted findings becoming machine-checkable
suppressions (U4). Raw tool output is never a finding and never a gate. The loop that makes it
compound is: `finding → rule (born with a test) → scored on our own 25-crate labeled corpus →
promoted by measured precision → retro-scanned over the whole corpus`.

---

## 1. The diagnosis this answers

`LESSONS.md` **L51**: the finder's mirror-walk is a **rank-1 (pairwise-semantic) projection** — it
compares *this* guard to *its* mirror, and its blind spots are exactly the dimensions that projection
collapses. `IMPROVEMENTS.md` **W20–W25** restore five of those dimensions as *prose lenses*. Prose
lenses have two structural defects:

1. **They cannot be exhaustive.** "Enumerate every enforcement site of this invariant" is a *promise*
   in a review brief. What actually happens is a `grep`, by hand, of the shapes the agent thought of.
   The h2/hyper/rustls campaigns each found real bugs at sites the mirror-walk *did* reach — we have
   no idea how many sites it never enumerated, because enumeration completeness was never measured.
2. **They cannot be regression-tested.** A lens that worked on rustls and silently stopped working on
   hyper produces the same output shape either way: candidates. There is no signal.

A rule file fixes both: it returns **every** instance of a shape, and it can be scored against a
corpus with known answers. That is the whole argument for putting a static-analysis layer in — not
"SAST finds bugs" (for our best findings it does not, see §11), but **"SAST converts a sampled walk
into an exhaustive worklist, and converts prose knowledge into a testable artifact."**

---

## 2. Four uses, four different success criteria

The single most important design decision: **U1 and U2 are different products with different gates.**
Conflating them is what makes SAST integrations fail — an enumerator with 200 hits is a healthy
worklist; a candidate rule with 200 hits is broken.

| | **U1 — Enumerator** | **U2 — Candidate feed** | **U3 — Signature memory** | **U4 — Negative memory** |
|---|---|---|---|---|
| **Output** | a *site inventory* (worklist) | candidate *cells* | rules distilled from our findings | machine-checkable suppressions |
| **Consumer** | the finder lens (W20–W25) | the finder lens, as extra cells | every future + past campaign | the triage/verify stage |
| **Optimize for** | **completeness** (recall→1) | precision *after* filtering | cross-target reuse | never re-litigating a refutation |
| **Noise tolerance** | high — it's a list, not an alert | low — agents cost money | n/a | n/a |
| **Gate** | enumeration-recall vs a hand-built ground truth | hits/kloc + measured precision | seed-recall == 1.0 + negatives pass | cites the original refutation |
| **Best layer (ADR-1)** | **protocol / state-machine** | **data-format parser** | all | all |

**U1 is the highest-value one and the least obvious.** For a protocol target, SAST cannot judge
whether a guard's mirror is missing — that is semantic. But it *can* return, exhaustively:

- every validation predicate in the crate (`fn is_valid_*`, `fn check_*`, every `-> Result<_, Error::…>`
  early-return) **and every call site of each**, so the mirror-walk works from a complete matrix
  instead of the sites an agent happened to grep (this is precisely how the h2 `is_valid_trailer_field`
  / connection-header finding was reached — by hand, non-exhaustively);
- every N-ary sink and which of its arms carries the guard (**W20**);
- every place two different units meet — bytes vs frames vs records vs windows (**W21**);
- every numeric bound whose threshold is attacker-influenced (**W27** value-range);
- every `with_capacity` / `reserve` / loop bound fed by a parsed length (**W27** allocation-provenance).

The agent stays the *comparator*; the rule becomes the *enumerator*. That division of labour is the
honest one, and it attacks the diagnosed root cause directly.

---

## 3. Tool layer — and the split that matters for the sandbox

**Tier-P (pattern engines) — no build, host-safe.** They read source. They never execute the target,
never run `build.rs`, never expand a proc-macro that we did not write. They may run on the
orchestrator side over a clean clone, like `novelty.py` already does.

**Tier-C (compiler-based) — requires a build, sandbox-required.** `clippy`, `dylint`, MIRAI, lockbud,
Miri all need the crate to compile. **Compiling an untrusted crate executes its `build.rs` and its
proc-macro dependencies at build time** — that is arbitrary code execution on the host. Tier-C
therefore runs **only inside the existing gVisor agent container** (`docs/agent-sandbox.md`,
`docs/security.md`), never on the orchestrator. This is not a nice-to-have: our targets are
attacker-adjacent third-party crates, and the tooling reference makes the same point about
dependencies (§11: "a `build.rs` / proc-macro in a new dep executes at build time → audit as
executable code").

| Tier | Tool | Role | Track | Notes |
|---|---|---|---|---|
| **P** | **OpenGrep** `v1.26.0` | U2 + U3 carrier | active | LGPL-2.1 fork of Semgrep 1.100.0; Semgrep-rule compatible; SARIF out; `--taint-intrafile` (flag name confirmed unchanged). The default *taint* engine. **Caveat below.** |
| **P** | **ast-grep** `v0.45.0` | U1 (structural enumeration) | active | Tree-sitter structural matching, Rust-native and Rust first-class; native YAML rule files + JSON out. The better fit when the output is a *worklist* rather than an alert. Engine choice is per rule, not global — see §4. |
| **P** | **CodeQL** | U2 for APP-TRUST-BOUNDARY | **BYOL**, opt-in | Best cross-file dataflow; queries are MIT, the CLI is not. See §10. |
| **C** | **clippy** (curated set) | U2 baseline | active | The `correctness` group + a cherry-picked `restriction` set (`unwrap_used`, `indexing_slicing`, `arithmetic_side_effects`, `as_conversions`, `undocumented_unsafe_blocks`). **Never all of `restriction`.** |
| **C** | **Dylint** | U3 for type-aware invariants | active | A Dylint lint is a *compiler* lint — HIR + types + macro-expanded code. The right home for rules a text matcher gets wrong. First three to write: the Rudra analyses (panic-safety, higher-order invariant, Send/Sync variance), since Rudra itself is archived and pinned to `nightly-2021-10-21`. |
| **C** | `cargo-geiger` | U1 (unsafe surface map) | active | Not a finder — an inventory. Feeds the unsafe-surface cell. |
| **C** | MIRAI (`endorlabs/MIRAI`) | U2, selective | **shadow** | Path-sensitive, expensive; run on parsers / crypto / authz cores only. Note the live fork — `facebookexperimental/MIRAI` is archived. |
| **C** | lockbud | U2 for `concurrency_async` targets | **shadow** | Deadlock / lock-order / atomicity. Capability-gated. |
| **C** | Rudra (frozen image) | U3 *source spec* only | **offline** | Archived 2026-04-02, ~50% FP, no suppression, no workspaces. Use as a **specification to port to Dylint** and as a periodic offline candidate generator. Never in-line. |
| **P** | `cargo-audit` / `deny` | supply chain | active | Orthogonal; already partly covered by `scan-extras.txt` §11. |

### 3.1 Measured: the Rust "default rule pack" is nearly empty — and that reshapes the plan

Counted inside the built image, 2026-07-28:

| source | Rust rules available out of the box |
|---|---|
| `semgrep/semgrep-rules` → `rust/lang/security/` | **10** (`.yml`, not `.yaml`) — `unsafe-usage`, `ssl-verify-none`, `insecure-hashes`, `rustls-dangerous`, `reqwest-accept-invalid`, `temp-dir`, `args`, `args-os`, `current-exe`, `reqwest-set-sensitive` |
| `trailofbits/semgrep-rules` → `rs/` | **1** (`panic-in-function-returning-result`) |
| **OpenGrep total for Rust** | **11** |
| clippy | **815** lints (332 opt-in `default_allow`, 416 `default_warn`, 67 `default_deny`) |
| Dylint (trailofbits `general`) | 9 lint libraries |

**Consequence.** For Rust, "run every engine's default rules" delivers, in practice, **clippy** — plus
nine Dylint lints and eleven pattern rules that are shallow audit-tier checks (hard-coded crypto,
disabled TLS verification, `unsafe` presence). This is the reference document's "classic taint SAST is
weak for Rust" headline, quantified: the community simply has not written Rust rules.

Two things follow, and both are corrections to the plan as written:

1. **OpenGrep's value here is almost entirely U3 (rules we write), not U2 (vendor defaults).** Rule
   authoring is not a "later, after pruning" phase for that engine — it is the *only* phase. Keep the
   11 running (they cost nothing), but do not expect a yield ledger to say anything about them.
2. **The pruning question narrows to clippy's opt-in tier.** That is where the noise will be, and
   `default_allow` (332 lints: pedantic ∪ nursery ∪ restriction ∪ cargo) is precisely the population
   under scrutiny. `clippy-driver -W help` does **not** publish group membership — the authoritative
   table needs network — so hits are tagged by *default level*, which answers the real question ("is
   the opt-in tier earning its noise?") without inventing a taxonomy we cannot verify offline.

**Tool facts, verified 2026-07-28** (the reference doc's snapshot was 2026-07-20; two entries moved):

- **OpenGrep is at v1.26.0 (2026-07-24)**, not the 1.22.0 the reference lists. There is **no official
  Docker image** — install via the upstream `install.sh` or a release binary (the repo ships only a
  self-build Alpine Dockerfile). Pin by version + checksum in our own image (§13 P0).
- ~~**The Rust taint path is the least-proven part of the whole design.**~~ **RESOLVED 2026-07-28 by
  direct experiment** (`rules/opengrep/rust/alloc-taint.yml`). Two separable answers:
  - **Rust taint genuinely works.** Verified with a negative control — a sink with no source stays
    silent — so the engine is really running, not vacuously matching. `--taint-intrafile` even
    crosses 2-hop helper chains and struct fields written in one fn and read in another. The
    assumption is discharged.
  - **And it still loses this class, 2/11 vs 11/11** against the syntactic `cls-alloc.yml` on
    identical ground truth. Three independent blockers, each fatal alone: the **macro wall**
    (`vec![$E; $N]` matches nothing as a taint sink, and taint cannot exit a macro either); **sources
    that are not byte reads** (lopdf's length is `dict.get(b"W")`, png's bound is `palette.len()`);
    and the **file boundary** — png's PLTE length crosses four hops, `u32::from_be_bytes` → struct
    field → a different struct → a different file, and intrafile analysis ends at hop four.
  - The apparent win evaporates on inspection: taint's source-connected tier finds 25 sites to
    cls-alloc's 2, but **all 23 extra are `skip`/`read_exact`/`extend_from_slice` sinks simply absent
    from cls-alloc's sink list** — a sink-vocabulary difference, not a dataflow one. FP ≥ 95 % on a
    uniform 40-hit sample (zero clear true positives).
  - **Worth harvesting anyway:** OpenGrep's `by-side-effect: true` sanitizer models `if n > CAP
    { return }` correctly and survives the adversarial unrelated-cap case that *silences* cls-alloc's
    tier 2b — two of that rule's four documented FP families, fixed. And its extra sinks belong in
    cls-alloc.
- **NEW, and larger than the taint question: OpenGrep cannot parse modern Rust.** 12 `PartialParsing`
  failures across **6 of 25 crates**; ast-grep parsed all 25 with zero errors. Constructs it chokes
  on: half-open range patterns (`7..`, `n @ 1..`), `&raw const` / `&raw mut` (stable since 1.82),
  inline `const` blocks, and `?Sized` in impl-Trait bounds. The last of those is
  `quinn-proto/src/packet.rs` — **the crate's core packet parser, partially analysed with no signal**.
  This affects search mode as well as taint, so it is an engine-selection fact, not a taint caveat.
  **A partial parse is indistinguishable from a clean one** — the same species as LESSONS L52, one
  layer down in the engine.
- **ast-grep is at v0.45.0 (2026-07-23)**; install via `cargo install ast-grep --locked` (no official
  Docker image either). Note the **`sg` binary name is deprecated** in that release — invoke
  `ast-grep`.

**Routing.** Which tools and which rule packs run is decided by the two classifiers this repo already
has, not by a global config:

- **ADR-1 `target_layer`** (stamped in `THREAT_MODEL.md` by the threat-model skill's Step 1.5) picks
  the *emphasis*: `protocol/state-machine` → U1-heavy, few U2 rules; `data-format parser` → U2-heavy;
  `API-contract` → differential/enumeration.
- **`capabilities.json`** (`harness/capabilities.py`, the §9 gate table) picks the *classes*: no
  `inbound_c_abi` → no FFI rules; no `concurrency_async` → no lockbud; no `unsafe_*` → no Rudra-ported
  Dylint lints. Every skip already carries a paper trail, which is exactly what keeps the noise budget
  honest.

This is the **W26 emphasis pack** made executable: the pack is a list of rule-pack ids plus additive
lens hints, keyed by `(target_layer, capabilities)`.

---

## 4. Data model

One interchange format: **SARIF**. OpenGrep, CodeQL, and (via `clippy-sarif`/`sarif-rs`) clippy all
emit it; ast-grep's JSON is trivially mapped. Everything downstream consumes the normalized shape, so
adding or dropping an engine never changes the artifact schema (§10 — this is what keeps
cross-campaign measurement uncounfounded).

```
  tool ──SARIF──▶ Hit ──dedupe/cluster──▶ Cell ──filter──▶ finder lens ──▶ Candidate ──▶ (existing verify)
```

**`Hit`** — one raw tool output, normalized:

```json
{
  "hit_id":   "sha1(engine|rule_id|file|line|snippet)",
  "engine":   "opengrep|ast-grep|clippy|codeql|dylint|geiger|mirai|lockbud",
  "rule_id":  "RIP-R014-counter-width-overflow",
  "mode":     "enumerate|candidate",
  "class":    "arith-overflow-counter",
  "lens":     "W21-unit-mismatch",
  "file": "src/name.rs", "line": 713, "symbol": "NamespaceResolver::push",
  "message": "...", "snippet": "...",
  "target": {"crate": "quick-xml", "commit": "<sha>"}
}
```

**`Cell`** — the unit an agent is allowed to see. A cluster of hits sharing `(class, module)`, plus
the filter verdict:

```json
{
  "cell_id": "quick-xml@<sha>/name.rs::arith-overflow-counter",
  "class": "arith-overflow-counter", "lens": "W21-unit-mismatch", "mode": "candidate",
  "hits": 11, "exemplars": ["src/name.rs:713", "src/reader/mod.rs:402", "..."],
  "filters": {"structural": "kept", "capability": "kept", "reachability": "yes|no|unknown",
              "where_checked": "lib.rs:44 pub use reader::Reader → Reader::read_event → …"},
  "dropped_siblings": {"test_code": 34, "not_pub_reachable": 12, "capability_gated": 0}
}
```

**`Candidate`** — unchanged. Cells enter the existing finder as *additional focus material*; whatever
the finder emits is a normal `F-NNN` / `FIND_SCHEMA` candidate and goes through the existing
union-of-N → 3-skeptic verify → independent-PoC gate. **No SAST hit ever bypasses that.**

---

## 5. The filter chain (and why it is affordable)

The noise numbers are known and bad — Rudra ~50 % FP, Yuga ~46 %, MirChecker 95 %. The chain is what
makes them payable. Four tiers, cheapest first, **every drop counted and logged** (no silent
truncation — that is W28's done-when and this repo's fail-loud discipline):

1. **Structural** (free, no agent). Drop `#[cfg(test)]`, `tests/`, `benches/`, `examples/`, `build.rs`,
   generated code, vendored deps. Drop modules not reachable from the crate's public re-export graph
   (parse `mod`/`pub use` from `lib.rs` — module granularity, cheap, no call graph needed).
   *Expected reduction: the largest single one.* This is the `fp-rules.txt` R5 exclusion, mechanized.
2. **Capability gate** (free). `capabilities.py::gates_for()` — already written. A class whose
   capability is `no` is dropped with the §9 evidence as the reason.
3. **Cluster** (free). `(class, module)` → cell. 10²–10³ hits collapse to ≲20 cells. **This is the
   cost control: agents judge cells, never hits.**
4. **Reachability judge** (1 cheap agent per *cell*). "Does attacker-controlled input reach this class
   of site in this crate? Name the entry point and the path." Answers `yes|no|unknown` plus a
   `where_checked` trace — deliberately the **same field name** `admissibility.py` already requires, so
   a SAST-originated candidate carries its reachability evidence in the pipeline's existing vocabulary
   and is gated by the existing code.

**Honest gap — checked, and the answer is "no tool".** Tier 4 is agent-judged because **no maintained
open-source tool answers "is function F reachable from the public API / entry E" at function
granularity on stable Rust** (verified 2026-07-28):

| candidate | why not |
|---|---|
| `cargo-call-stack` | LLVM-IR call graph filterable from a start point — but needs nightly `-Z stack-sizes`, and upstream itself calls it "of very limited use" on std-linked (non-embedded) code because of indirect calls |
| `cargo-modules` | crate structure / module dependencies, not per-function calls |
| `cargo public-api` | public-surface diffing; needs nightly rustdoc JSON; answers "what is public", not "what reaches what" |
| `rust-analyzer` | has a call hierarchy, but LSP/IDE-only — no batch CLI, and the feature has open correctness bugs |
| **`reachsec`** | new/experimental, and asks *exactly* our question ("is advisory-flagged function F reachable"), but its `callgraph4rs` engine pins a specific nightly + `rustc-dev`. **Watch item, not a dependency** |
| **MIRAI** | emits dot/JSON call graphs at **callsite** granularity — research-grade and imprecise under indirection, but it is *already* in our nightly shadow image |

So tier 1's module-level approximation plus one agent per *cell* is the pragmatic answer, not the
elegant one — and it is the state of the art available, not a shortcut. Two upgrade paths, both
deferred to P5 and neither load-bearing: **MIRAI's call graph as a reachability *input*** (it is
already being built for other reasons — a cheap experiment: does its graph agree with the agent
judge?), and **reachsec** if it ever unpins from nightly. If either lands, tier 4's agent becomes a
computed answer and this design gets strictly cheaper.

**Cost model per target:** ~500 raw hits → ~120 after structural → ~15 cells → 15 cheap agent
judgments → 3–5 surviving cells into the finder brief. That is a fraction of one find pass.

---

## 6. The signature-expansion loop

This is the part that compounds. Everything above is a scan; this is the memory.

```
        ┌────────────────────────── corpus (§7): N crates, pinned, cached ───────────────────────┐
        │                                                                                         │
        ▼                                                                                         │
  [sast run] ─▶ hits ─▶ filter ─▶ cells ─▶ finder lens ─▶ candidates ─▶ verify (existing)         │
                                                                            │                     │
                        confirmed ── contested ── refuted ──────────────────┤                     │
                                                                            ▼                     │
                                                            [distill]  pattern ─▶ rule + tests    │
                                                                            │                     │
                                                                            ▼                     │
                                                            [score] ────────────────────────────▶─┘
                                                                            │
                                                                            ▼
                                                            [promote] draft → shadow → active
                                                                            │
                                                                            ▼
                                                            [retro-scan] the whole corpus
                                                                            │
                                                                            ▼
                                            net-new candidates in targets we already finished
```

### 6.1 Distill — the seed is a *pattern*, from *any* disposition

Straight from [`variant-analysis.md`](variant-analysis.md): the seed is a **pattern**, not a finding,
and it comes from **confirmed, contested, AND refuted** candidates — control coverage of a pattern is
non-uniform, so a refuted candidate is a worked example of *what the correct guard looks like*, which
is the single best thing to diff every sibling against. Three seed sources, as there:

- (a) our confirmed findings, (b) our refuted findings, (c) the project's **historical advisories +
  their fix commits** (the highest-grade seed: a curated pattern with the exact added control pinned).

The distillation is the existing `/variant-scan` CVE pass, **made persistent**. Today that pass
re-derives the pattern from prose every run and forgets it afterwards. A rule file is the same
knowledge, executable and permanent.

### 6.2 Every rule is born with a test

A rule is not accepted without both, extracted from the same crate as the seed:

- **positive** — the seed site *must* match. (`quick-xml@<sha>:src/name.rs:713` for the u16
  `nesting_level` counter overflow.)
- **negative** — the *guarded siblings must not* match. (`reader/mod.rs` and `de/mod.rs` `depth`, which
  are `i32` and therefore unreachable; `name.rs` `count`, which is `usize` and capped.)

This single requirement is what separates a rule pack from junk: it forces the author to encode **the
guard's presence**, not just the dangerous shape. A rule that matches guarded and unguarded instances
alike is a `grep`, and it fails the negative test.

### 6.3 Score — on our own corpus, with five numbers

Reuse the labeled-corpus schema `profiles/rust/fp-rules.txt` already defines (five numbers, never one
"specificity"; `real_latent` is never in the FP denominator — **R11**). Per rule:

```json
"score": {"corpus_rev": "2026-07-28", "seed_recall": 1.0, "negatives_pass": true,
          "raw_hits": 143, "post_filter": 11, "hits_per_kloc": 0.9,
          "known_tp": 2, "known_fp": 4, "real_latent": 1, "unknown": 4,
          "precision_est": 0.33, "enumeration_recall": null}
```

### 6.4 Promote — different gates for U1 and U2

| transition | `mode: candidate` gate | `mode: enumerate` gate |
|---|---|---|
| draft → **shadow** | `seed_recall == 1.0` **and** all negatives pass | same |
| shadow → **active** | `hits_per_kloc ≤ 0.5` post-filter **and** `precision_est ≥ 0.3` on a triaged sample **and** ≥1 `unknown` that survived verify (it must have *earned* recall, not just been quiet) | `enumeration_recall ≥ 0.95` against a hand-built ground-truth site list for one corpus crate — precision is explicitly **not** a criterion |
| active → **gate** | precision 1.0 across the corpus **and** a maintainer-facing reason to block a PR. Expected to be **rare**; the tooling reference is right that none of the research-grade tools belongs in a blocking gate | n/a |
| any → **review** | FP rate rises on new campaigns, or 5 campaigns with 0 fires, or the seed site stops matching (the crate moved — that is a signal to re-verify the *finding*, not just the rule) | same |

`shadow` rules run and feed **cells only** — never a candidate, never a report line. This is the
two-track discipline from the WAAP work (detection-only vs enforcing) applied to a rule corpus, and it
is the reason a 50 %-FP tool like a Rudra port can be in the pipeline at all.

### 6.5 Retro-scan — the payoff

The moment a rule reaches `active`, run it across **the whole corpus**, not just the current target.
We have ~25 crates already cloned, pinned, threat-modelled, and campaigned. **Every new rule is
instantly a 25-target variant sweep**, at grep cost. This is where "переиспользовать находки" becomes
concrete: a pattern learned on `quick-xml` gets tested against `lopdf`, `object`, `gimli`, `h2`,
`rustls` the same day, with zero incremental agent spend until a hit survives the filter chain.

### 6.6 Negative memory (U4)

A refuted candidate yields two artifacts, not one: a **rule** (§6.1) and a **suppression** — a
machine-checkable entry that says "this class, at this shape, with this guard present, was refuted on
`<date>` for `<reason>`; cite `<verdict>`". `profiles/rust/fp-rules.txt` R1–R11 are these, in prose;
the suppression file is the executable form, and it prevents the pipeline from paying twice for the
same refutation across campaigns. A suppression must cite the original verdict, and it never applies
across a crate boundary silently — it names the crates it was validated on.

---

## 7. The corpus — the thing that makes this measurable

Everything above depends on a labeled ground truth. **We already have one and it is not yet
assembled.** Inputs that exist today:

- the internal disclosures ledger — 56 findings / 81 artifacts, with crate, repo, severity, channel,
  outcome. **Missing: `file:line`, the pinned commit, and the fix commit.**
- the `*-disclosure/` and `*-pr/` packages — each REPORT carries the exact `file:line` and mechanism.
- `targets/*/THREAT_MODEL.md` — carries the **Pin:** sha and the `target_layer` stamp.
- `targets/*/JOURNAL.md` and the campaign lessons — carry the **refuted** candidates, which are half
  the value (§6.1) and exist nowhere machine-readable.

**Work item:** `corpus/findings.jsonl`, one row per finding — `{finding_id, crate, repo, commit,
file, line, symbol, class, lens, disposition ∈ confirmed|refuted|contested|wontfix, fix_commit,
advisory}` — plus `corpus/pins.jsonl` and a clone cache keyed by `(repo, commit)` (the same shape
`novelty.py`'s cache already uses). This is a few hours of extraction and it is the prerequisite for
every measurement in §6.3–6.5. Without it the rule pack is unfalsifiable and this whole design is
prose again.

---

## 8. Surfaces, CLI, and file layout

The layer must work in **both** of this repo's execution modes:

- **skill mode** (how every real-OSS campaign actually ran — `targets/h2`, `targets/hyper`, `lopdf`, …
  have a `THREAT_MODEL.md` and no `config.yaml`): Tier-P tools run read-only on a local clone; no
  docker, no build. This is the common path.
- **pipeline mode** (`targets/*/config.yaml` + an image): Tier-C tools run inside the agent container
  as a stage between `recon` and `find`.

**Built 2026-07-28** (v1): `docker/sast/` (image + two-phase runner + batch driver),
`.claude/skills/sast-driven/` (+ `.agents` twin), `rules/astgrep/` (the U1 enumerator + `cls-*` class
rules), `corpus/pins.jsonl`. See [`docker/sast/README.md`](../docker/sast/README.md). CodeQL BYOL
wiring added 2026-08-03 — see §10.0.

```bash
# skill mode — the isolated 4th mode
/sast-driven <crate>                          # runs the image, judges cells, writes SAST-FINDINGS.json
/variant-scan <target-dir> --passes blind,tm,cve,sast     # the 4th seed source

# pipeline mode
vuln-pipeline sast <target>                   # Tier-P + Tier-C (in-container), SARIF → hits → cells
vuln-pipeline sast <target> --byol codeql     # opt-in, see §10

# the loop
vuln-pipeline distill <results-dir>           # candidate(any disposition) → draft rule + tests
vuln-pipeline rules score  [<rule-id>]        # run against corpus/, write the five numbers
vuln-pipeline rules promote                   # apply the §6.4 gates; report every transition
vuln-pipeline rules retro  <rule-id>          # sweep the whole corpus with one rule
```

```
rules/
  META.jsonl                 # one row per rule: id, engine, mode, lens, class, provenance, score, track
  opengrep/rust/*.yaml       # Tier-P, Semgrep-compatible (portable — also runs under Semgrep CE)
  astgrep/rust/*.yml         # Tier-P, structural enumeration
  dylint/                    # Tier-C, a cargo workspace of type-aware lints (Rudra ports live here)
  codeql/rust/*.ql           # BYOL — queries only, never the CLI
  tests/<rule-id>/{positive,negative}.md   # the §6.2 fixtures: corpus refs, not copied source
corpus/
  pins.jsonl  findings.jsonl  suppressions.jsonl
harness/sast/
  runner.py normalize.py cluster.py filter.py distill.py score.py promote.py
```

**Rule ids** are stable and citable: `RIP-R<nnn>-<slug>`. A finding's report can then say "found by
`RIP-R014`, distilled from `quickxml-nsresolver-u16-overflow`" — provenance all the way from a
disclosed bug to the rule that generalized it. Rule provenance also protects against a subtle failure:
a rule that only ever re-finds its own seed looks productive in the metrics until you check
`unknown > 0`.

### 8.1 Where it plugs into the existing pipeline

| existing thing | change |
|---|---|
| `threat-model` Step 1.5 (ADR-1) | additionally stamps the **rule packs + emphasis pack** for the layer (W26) |
| `recon` | cells become extra focus-area material; a cell with `reachability: yes` is a strong focus signal |
| `/vuln-scan` `--extra` | unchanged; the SAST cells are appended as *additive* hints ("attend to…", never "only look for…") |
| `/variant-scan` | gains a **4th pass**: `sast` alongside blind / tm / cve — same union + 3-skeptic verify |
| `harness/feedback.py` | new edges: **P8a** `candidate(any disposition) → distill`, **P8b** `new active rule → retro-scan`, **P8c** `refuted → suppression`. Same pure-decision style as the existing three edges |
| `harness/capabilities.py` | `_GATES` gains rows mapping capability → rule-pack ids |
| `admissibility.py` | unchanged and load-bearing: a SAST-origin candidate carries `where_checked` from the §5 tier-4 judge, so the existing gate applies with no new code |
| `profiles/rust/fp-rules.txt` | gains a pointer to `corpus/suppressions.jsonl` — prose rules stay the human contract, the JSONL is the machine twin (same split as `capabilities.md` ↔ `capabilities.py`) |

### 8.2 Is this a new *mode*? — stage yes, profile no

The repo has four orthogonal axes and it matters which one this lands on:

| axis | today | where SAST lands |
|---|---|---|
| **profile** (`rust`, `cpp`, `android-app`) | selects the bug-class family → find/grade/report prompts + detector | **not a profile.** SAST is *cross*-profile; it **consumes** one. Rule packs are namespaced per profile (`rules/rust/…`), so a profile gains a pack, not a twin. Making it a profile would be a category error — there is no "SAST bug class". |
| **stage** (`recon`, `run`, `grade`, `report`, `dedup`, `patch`, `predisclose`, `reattack`, `scorecard`) | pipeline subcommands | **yes — one new stage**, `vuln-pipeline sast`, sitting between `recon` and `find`, plus the three loop subcommands (`distill`, `rules …`). |
| **pass** (`/variant-scan`: `blind`, `tm`, `cve`) | seed-diverse find passes | **yes — a 4th pass**, `--passes blind,tm,cve,sast`. Same union + 3-skeptic verify, no new machinery. |
| **mode** (inside the stage) | — | **two, not four**: `enumerate` (U1) and `candidate` (U2), a per-rule field. U3/U4 are *loop* phases, not run modes. |

So: **one stage, one extra pass, two rule modes, zero new profiles.**

### 8.3 Packaging: a `vuln-pipeline-sast` tool image — yes, and it changes the architecture for the better

None of OpenGrep / ast-grep / Dylint / cargo-geiger is installed on a typical operator host (verified:
on this machine only `cargo-clippy` and `cargo-miri` exist). Asking the operator to install a
seven-tool analysis stack by hand is how a layer like this dies. Build the image.

**The idiom already exists.** `harness/agent_image.py` builds a shared
`vuln-pipeline-agent-base:<cli-version>` **once**, caches it by tag, and layers per-target `/work` on
top. The SAST image is the same move with one structural difference: **it is target-independent.**
Every existing image is per-target (the crate is `COPY`'d in and built); this one is per-*tool-pack*,
and the target source arrives as a **read-only bind mount** — which `docker_ops.run(mounts=…)` already
appends `:ro` to, and `exec_sh` already drives.

```
  vuln-pipeline-sast:<pack-rev>        Tier-P + stable Tier-C — the default
    opengrep · ast-grep · rust stable + clippy + clippy-sarif/sarif-fmt · cargo-geiger · dylint
    mount:  <clone>:/src:ro   <cargo-home>:/cargo:ro   rules/:/rules:ro   [<codeql>:/opt/codeql:ro]
    run:    --network none, gVisor runtime, --offline

  vuln-pipeline-sast-nightly:<pack-rev>   shadow track only — MIRAI, lockbud, Miri
    (nightly-pinned, heavy, high FP; never gates anything — keep it out of the default image)

  ghcr.io/sslab-gatech/rudra:master        used as-is, upstream's frozen image, offline batch only
```

**Four things this buys, beyond convenience:**

1. **It solves the measurement-confound risk (§12) properly.** The image digest pins every tool
   version, so a score's full key is `(corpus_rev, image_digest, rule_pack_rev)`. "Did the rule pack
   improve recall?" becomes answerable because the only moving part is the one you changed. A manifest
   note could never give that.
2. **It collapses the Tier-P / Tier-C host-vs-container split into an implementation detail.**
   Everything runs in the container under gVisor with `--network none`. The tiering survives only as
   "does this tool need `cargo` to resolve and build?", which decides whether the pre-fetch step below
   is required — not as a security boundary the operator has to remember.
3. **`build.rs` never executes on the host.** Tier-C compiles the target, which runs its build scripts
   and proc-macros — arbitrary code from an untrusted crate. In-image, that lands inside the same
   sandbox the find agents already run in.
4. **BYOL becomes trivially clean.** The image ships a `/opt/codeql` mount point and no CodeQL. An
   operator who holds a license bind-mounts their own CLI there and passes the attestation flag.
   No CLI in our artifact, no download step, no licensing ambiguity — the BYOL contract (§10) is
   enforced by the packaging rather than by a policy sentence.

**The dependency wrinkle, and its fix.** Tier-C needs the crate's dependency graph on disk, but the
container has no network. Resolve it the way `novelty.py` already resolves its network need — on the
orchestrator: `cargo fetch --locked` **downloads without building**, so no `build.rs` runs, then the
populated cargo home is mounted read-only and the container runs `--offline`. Net effect: untrusted
code never executes outside the sandbox, and the sandbox never gets network. Both invariants hold.

**Fallback when Docker is absent.** Tier-P is pure source reading, so `/sast-scan` in skill mode may
run host-installed OpenGrep/ast-grep if the operator has them — but the run manifest records
`engines: host` and such a run is **not admissible for rule scoring or promotion** (unpinned tool
versions). Exploration yes; measurement no.

---

## 9. What a rule looks like (three worked shapes)

**U2 candidate rule (OpenGrep, taint).** The shape that pays off most — untrusted length → allocation
(**W27** allocation-provenance):

```yaml
rules:
  - id: RIP-R021-alloc-from-parsed-length
    languages: [rust]
    mode: taint
    pattern-sources:
      - pattern: $R.read_u32::<$E>()?
      - pattern: $R.read_u16::<$E>()?
    pattern-sanitizers:
      - pattern: $N.min($CAP)
      - pattern: if $N > $CAP { ... }
    pattern-sinks:
      - pattern: Vec::with_capacity($N)
      - pattern: vec![$X; $N]
    message: allocation sized by a parsed length with no cap on the path
    severity: WARNING
```

The `pattern-sanitizers` block *is* the negative test from §6.2 — it encodes what "guarded" looks like.

**U1 enumerator (ast-grep).** Not an alert — an inventory feeding the mirror walk:

```yaml
id: RIP-E003-validation-predicates
mode: enumerate
language: rust
rule:
  any:
    - pattern: fn is_valid_$NAME($$$) -> bool { $$$ }
    - pattern: fn check_$NAME($$$) -> Result<$$$> { $$$ }
# emit: every match + every call site of each match → the mirror-walk matrix
```

**U3 type-aware rule (Dylint).** The class a text matcher gets wrong — a Rudra port:

```
unsafe impl<T> Send for X<T>  with no T: Send bound, over a type holding *mut T / NonNull<T>
→ needs HIR + the actual type of the field. Text matching cannot see the bound relationship.
```

---

## 10. BYOL CodeQL — the contract

CodeQL is the strongest APP-TRUST-BOUNDARY finder (Rust GA in 2.23.3, Oct 2025; all OWASP categories
except A06). Its queries are MIT; **the CLI is separately licensed**, and analysing closed source may
require a commercial license. So:

1. **This repo ships queries only** (`rules/codeql/`), never the CLI, never a binary, never a
   download step.
2. **Activation is triply explicit**: the `--byol codeql` flag **and** `codeql` on `PATH` **and**
   `sast.byol.codeql.attested: true` in the run config, by which the operator asserts they hold the
   right to run it on this target. Never auto-enabled, never enabled by presence alone.
3. **Role**: one additional *finder* in the union, with its own lens id (`codeql-security-extended`),
   restricted to the APP-TRUST-BOUNDARY family where it beats the pattern engines. It does not
   replace OpenGrep — an independent second finder is worth more than a marginally better single one.
4. **Determinism requirement**: the downstream artifact schema is **identical** whether CodeQL ran or
   not, and the run manifest records which engines participated. Otherwise "did the rule pack improve
   recall?" becomes unanswerable — a confound, not a measurement.
5. **Known constraints to encode**: needs `rustup`+`cargo`; **nightly is not supported** (so it cannot
   analyse a nightly-only target — `rust-canary` builds with `+nightly -Zbuild-std`); uses
   `build-mode: none`, which conveniently makes it **Tier-P** (no build → host-safe).
6. **Licence terms, read at source 2026-07-28** (`github/codeql-cli-binaries/LICENSE.md`) — the grant
   is narrower and more precise than "free for public repos":
   - Permitted free: *"Perform analysis on the **Open Source Codebase**"* and *"generate CodeQL
     databases for or during automated analysis, CI, or CD"*, where an Open Source Codebase is one
     **hosted and maintained on GitHub.com** under an OSI-approved licence; plus *"academic
     research"* and testing OSI-licensed queries.
   - Prohibited without GitHub Advanced Security: generating a database for *"any codebase that is
     not an Open Source Codebase (e.g., code in a private repo)"*.
   - **The permission depends on WHAT is analysed, not on who runs it.** All 25 corpus crates and
     DVRA are GitHub-hosted under MIT/Apache-2.0, so campaign use is squarely inside the grant. A
     crate mirrored off GitHub, a private fork, or the operator's own proprietary code is *outside*
     it — which is what the attestation flag now means concretely rather than cautiously.
   - The licence also forbids *"share, publish, distribute or **lend** the Software"*, which
     independently confirms §8.3's design: the CLI is **never baked into the image**; it arrives
     through the `/opt/codeql` bind mount that the operator supplies.

The same contract shape applies to any future proprietary engine. Nothing in the pipeline may
*require* it.

### 10.0 Implemented interface (wired 2026-08-03)

The contract above is the design; here is what is actually built today, so a reader runs the working
path rather than the aspirational one:

- **Activation is by mount, at the `sast-scan.sh` / `/sast-driven` level** — not a `vuln-pipeline sast`
  subcommand (that subcommand and the `sast.byol.codeql.attested` config key remain design; the CLI
  entry point is `docker/sast/sast-scan.sh` + the skill). Set `SAST_CODEQL_CLI` to a Rust-capable
  CodeQL distribution on the box (the skill exposes this as `--byol codeql`). `sast-scan.sh` then
  bind-mounts it read-only at `/opt/codeql`, appends `codeql` to `SAST_ENGINES`, and `run-all.sh`
  runs `codeql database create --language=rust --build-mode=none` + `database analyze` over
  `rules/codeql/rust`, writing `codeql.sarif` into `raw/` where `normalize.py` already ingests it
  (`ARTIFACTS`). **Supplying the mount IS the attestation-by-action** the contract's item 2 asks for;
  the operator asserts the right to analyse this target by providing the CLI.
- **Knobs**: `CODEQL_CREATE_FLAGS` (default `--build-mode=none`), `CODEQL_QUERIES` (default
  `/rules/codeql/rust`), `CODEQL_ADDITIONAL_PACKS` (point at the dist's `qlpacks` if `codeql/rust-all`
  is not otherwise resolvable offline).
- **Off by default**: absent `SAST_CODEQL_CLI` / `codeql` in `SAST_ENGINES`, the block does not run
  and — being opt-in BYOL — does not record a spurious `absent` for a non-selected engine.
- **Not yet exercised in-repo**: there is no CodeQL CLI in CI, so this path is wired but unvalidated
  end-to-end here; the first real BYOL run is its acceptance test.

### 10.1 Measured 2026-07-28 — CodeQL is a *second* generator, not a better one

The port ran (`rules/codeql/rust/`, 8 queries, ~1.3k lines) and was A/B'd against the ast-grep pack on
the same crates, with a purpose-built fixture whose answers are encoded in the function names.
**Verdict: adopt as a complementary generator; never as a replacement.** The two engines fail in
*disjoint, structural* places — not places tuning can move.

First, a caveat from the earlier probe is **resolved, and it was a misreading of a counter.** "Rust
files extracted with errors: 85" counts files with ≥1 *failed macro expansion*, not dropped files.
Measured DB-wide: `Unextracted`/`Missing`/`Unimplemented` = **0/0/0** on all three databases, crate
files 101/101, 36/36, 33/33, per-file function counts matching source exactly. The one real gap is
lopdf `src/reader.rs` 53/72 — precisely its 19 `#[cfg(feature = "async")]` functions, unresolvable
offline. **The extractor is sound**, so a CodeQL zero is not automatically void.

But a *different* number is genuinely broken, and it explains the built-in query's zero:

| macro calls expanded | lopdf | image-png | miniz_oxide |
|---|---|---|---|
| overall | 1040/7189 (14.5 %) | 73/663 (11.0 %) | 166/293 (56.7 %) |
| **`vec!`** | **0/285** | **0/93** | **0/15** |

An AST probe of the exact line lopdf PR #533 fixed returns `MacroCall "vec!…"` → `TokenTree` → and
nothing else: no text accessor, no children. **The size expression is not in the database.** That —
plus `ActiveThreatModelSource` being empty in a library crate — is the whole reason
`rust/uncontrolled-allocation-size` returned 0. Not a tuning problem; the data isn't there.

| class | winner | evidence |
|---|---|---|
| recursion, **mutual** | **CodeQL** | ast-grep cannot express a call graph at all. Real cycles only it sees: quick-xml `normalize_attr_steps ↔ normalize_attr_step`, lopdf `write_object ↔ write_array/dictionary/stream`, `traverse_object ↔ …`, `encrypt/decrypt_object` |
| recursion, **serde re-entrancy** | **ast-grep 6/6, CodeQL 0/6** | re-entry goes through a caller-chosen generic; `deserialize_seq` resolves to `<<UNRESOLVED>>`. Monomorphisation unknown → the cycle breaks exactly at the interesting edge |
| unguarded pop | **CodeQL** | same ground truth (ttf-parser `cff2.rs:383`) found by both; volume 41 → 15 corpus-wide with **every** drop verified arity-correct, incl. the compound-condition guards cls-pop's own header lists as "CANNOT see". Fixture: ast-grep 4 TP + 7 FP, CodeQL 4 TP + **1** FP |
| allocation, `vec!`-shaped | **ast-grep** | the headline lopdf site is unreachable by *any* dataflow config (see the macro table) |
| allocation, dataflow | **CodeQL** | 4/4 with a source→sink path through a helper return, a struct field, and a cross-type field read, vs 1/4 source-connected for ast-grep; and its per-value `BarrierGuard` has none of cls-alloc's "any unrelated cap in the same function silences everything" hole |
| type disambiguation | **CodeQL, decisively** | `runpaths.join(&[b':'][..])` resolves to `alloc/src/slice.rs` while the control `p.join(s)` resolves to `std/src/path.rs`. The `Path::join`/`slice::join` FP that cls-limit documents as needing a type-aware engine **is separable**, cheaply |

Two operational consequences, both mandatory:

- **`ExtractionCoverage.ql` runs on every new database before any silence is trusted.** Both failure
  modes above — macro opacity and unresolvable-`cfg` arms — are silent *by construction*. This is the
  same instrumentation duty as L52's `partial` status, in a second tool.
- Cost: DB build ≈ 70 s/crate, query eval 10 s–5 min. Cheap enough to run on the whole corpus.

A fifth result worth keeping: four bugs in the agent's own query drafts had **one shared root cause** —
`toString()` abbreviates composite nodes, which silently broke depth-bound detection, `#[cfg(test)]`
exclusion, `&[u8]` parameter typing, and `Some(_)` matching. In QL as in ast-grep, the engine's
*display* of a node is not the node.

### 10.2 Measured 2026-07-29 — the CodeQL BUILT-IN pack is empty on this target class (W35)

§3.1 measured that vendor-default rule packs are near-empty for Rust (OpenGrep: **11** Rust rules).
The obvious objection was that CodeQL is the serious engine and its shipped pack would be different.
It is not. The full `rust-security-extended` suite — **all 18 security queries** plus diagnostics,
CodeQL 2.26.1 / `rust-queries` 0.1.38 — was run over the whole corpus. The extraction gate
(`ExtractionCoverage.ql`, per L53) passed on every database first, so every zero below is a real zero:

| crate | files extracted | security hits |
|---|---|---|
| image-png | 36 | **0** |
| miniz_oxide | 33 | **0** |
| msgpack-rust | 79 | **0** |
| object | 145 | **0** |
| quick-xml | 79 | **0** |
| ttf-parser | 87 | **0** |
| lopdf | 101 | 109 — *see below* |

`uncontrolled-allocation-size`, `path-injection`, `access-invalid-pointer`,
`access-after-lifetime-ended`, `sql-injection`, `regex-injection`, `request-forgery` and the rest:
**zero on all seven.** And lopdf's 109 are not an exception, they are the illustration:

- 99 × `hard-coded-cryptographic-value`, of which **76 sit in `tests/` and `examples/`** — hard-coded
  passwords in test fixtures. The pack ships no path exclusions, which is §6's point in the external
  implementation guide made concrete: a versioned exclusion list is part of a rule pack, not an
  afterthought.
- 10 × `weak-cryptographic-algorithm` → RC4 and MD5 in `src/encryption/algorithms.rs`. lopdf
  *implements the PDF standard security handler*, which mandates exactly those algorithms. Flagging
  them is flagging the format.

**Reading.** This is not a defect in CodeQL. The built-ins target the web/service classes — injection,
TLS config, secret hygiene, SSRF, XSS — and a byte-parser library has none of them: no request, no
query, no connection, no template. It confirms §3.1's conclusion on the stronger engine and settles
the strategic question the whole layer opened with: **for our target class the ground-truth-built rules
are not a supplement to vendor defaults, they are the entire yield.** The BYOL contract still pays for
itself — but through §10.1's custom queries (mutual recursion, pop dominance, type disambiguation), not
through anything GitHub ships.

Artifacts retained out-of-band, not in the repo.

### 10.3 Miri, wired as an oracle — validated on a paired vuln/patched crate

The pipeline used Miri nowhere. It is now a named oracle in the find→fuzz dispatch, with a dedicated
template: [`profiles/rust/harness-templates/panicking_drop.rs`](../profiles/rust/harness-templates/panicking_drop.rs).

The class it decides is the one no engine in this layer can reach — *break an ownership invariant → call
code that may unwind → restore the invariant*, where the restore never runs and the container's own
`Drop` then observes an impossible state. Every line of the trigger is safe Rust.

Validated against paired ground truth rather than asserted, using the W33 method on a single advisory
(thin-vec, RUSTSEC-2026-0103 / CVE-2026-6654, patched `>= 0.2.16`):

| | thin-vec 0.2.15 (TP) | thin-vec 0.2.16 (TN) |
|---|---|---|
| same harness, same flags | `error: Undefined Behavior: memory access failed: alloc1209 has been freed, so this pointer is dangling` — a double free of the element's `Box` | both probes unwind cleanly, no UB |

Two harness details were each measured, and each is the difference between an oracle and a silent pass:

1. **The payload must own heap memory.** With a bare `usize` element, *both versions passed* — dropping
   a POD twice is a no-op at the memory level, so Miri saw nothing on a container that was
   demonstrably double-dropping.
2. **The fuse must fire exactly once.** Panicking on every drop makes the erroneous second drop panic
   again; Rust aborts on a panic during cleanup, and `panic_in_cleanup` *masks* the memory error.

Both are recorded in the template header, because a harness that cannot separate the pair is not an
oracle — and the cheap check for that is to run it against the patched version too, always.

---

## 11. Honest limits, and the experiment that must run first

**What this layer would NOT have found.** Every headline finding of the current arc is
PROTOCOL-LOGIC: the h2 trailers §8.2.2 violation, the rustls QUIC downgrade and the 2-path
`quic:None` panic, the httparse whitespace-line header truncation. **No SAST finds any of
them** — the defect is a disagreement between two parsers, or a missing mirror of a semantic
invariant, and the tooling reference's own PROTOCOL-LOGIC row says "none — seeds only". Any pitch of
this layer that implies otherwise is dishonest and will produce exactly the low-SNR fan-out that got
us maintainer pushback once already.

**So the design must be falsifiable.** Before believing any of it, run this on our own data:

> **⚠ E1 as specified below was superseded on 2026-07-28 by the "prune, don't pick" amendment**
> (ADR-2): v1 runs **every engine's default rules** and measures yield per rule/group across the
> corpus, instead of hand-authoring a small rule set to test the premise. The *measurements* below
> are unchanged and still the gate — only the rule source changed (vendor defaults + our five U1
> enumerators, rather than 6–8 hand-written rules). Read the phrasing accordingly; `PRUNE-LEDGER.md`
> from the `sast-driven` mode is where E1's numbers now land.
>
> **Experiment E1 — retro-validation on the finished campaigns.** Write 6–8 rules encoding W20 / W21 /
> W27 and the specific patterns from four *already-disclosed* findings. Run them against the pinned
> commits of h2, hyper, rustls, quick-xml, lopdf, object. Measure three things:
>
> 1. **U2 recall** — do the candidate rules re-find our own confirmed findings? *Prediction: yes for
>    the parser/arith/alloc findings (quick-xml u16 counter, lopdf recursion, miniz init_tree),
>    **no** for every protocol-logic finding.* If the protocol ones come back
>    positive, be suspicious of the rule, not pleased.
> 2. **U1 completeness** — does the enumerator return the sites the mirror walk actually used
>    (`is_valid_trailer_field` and every call site; the `recv_open`/`inc_num_recv_streams` pair; the
>    rustls `usable_for_protocol` filter and its missing mirror)? **And what does it return that the
>    walk never visited?** That residue is the measurement of the L51 blind spot — the first direct
>    evidence of how much the rank-1 projection was collapsing.
> 3. **Noise** — hits/kloc pre- and post-filter, per tier, per tool.
>
> **A clean negative on (1) plus a positive on (2) is the expected and useful result**: it says SAST's
> role here is enumerator + memory, not finder, and the design should be trimmed to that.

E1 costs one session, needs no new infrastructure beyond the corpus pins, and decides whether P1–P3
below are worth building.

---

## 12. Risks

| risk | mitigation |
|---|---|
| **Reachability filter is load-bearing and has no OSS tool** — *checked 2026-07-28, confirmed*: every candidate is nightly-pinned, embedded-only, IDE-only, or research-grade (§5). | Tiered approximation: free structural module-reachability does most of the work; one agent per *cell* does the last mile; `where_checked` keeps the answer auditable. Two deferred upgrade paths (MIRAI's call graph, `reachsec`), neither load-bearing. |
| **The OpenGrep Rust taint path is unproven** — Rust is supported and `--taint-intrafile` exists, but upstream's taint tutorial demonstrates only Python/JS. The §9 taint rule shape is an *assumption*. | E1 tests it first. Fallback: structural rules with explicit sanitizer patterns (expressible in both engines). U1/U3/U4 do not depend on taint at all, so a negative result costs one of four uses, not the design. |
| **The rule pack rots.** Crates evolve; rules silently stop matching; the pack looks healthy because it is quiet. | `seed_recall` is re-scored every corpus refresh; a rule whose seed stops matching goes to `review` — and that is *also* a signal to re-verify the finding upstream. "0 fires in 5 campaigns" triggers review. |
| **Noise floods the finder anyway.** | Cells, not hits, reach agents; `shadow` track never produces candidates; drops are counted so a regression in the filter is visible instead of silent. |
| **Rule-shaped tunnel vision** — the finder starts looking only where rules point, and the "unexpected class" recall (the blind pass's whole value) drops. | Hard constraint, already the user's standing correction: SAST cells are **additive hints** ("attend to…"), never a restriction; `/variant-scan` keeps its blind pass unweighted and unseeded; if the blind pass's unique-finding rate drops after SAST lands, that is a regression to investigate. |
| **Tier-C executes untrusted `build.rs`.** | Tier-C runs only in the gVisor container. Tier-P is the host-safe default and covers U1/U3 almost entirely. |
| **Measurement confound from a changing tool set.** | The run manifest pins engine versions + rule-pack revision; scores are always `(corpus_rev, engines)`-stamped. |
| **CodeQL licensing creep** — someone runs it on private code without rights. | Triple-explicit activation (§10.2); the repo ships no CLI; the attestation is recorded in the manifest. |

---

## 13. Implementation plan

Ordering principle: **the image comes first, because nothing can be measured without it** (no analysis
tool is installed on a typical operator host), and **the falsifier comes before the spine**, because
P3+ is only worth building if E1 says the premise holds. Each phase names its files, its acceptance
test, and the reason to stop.

### P0 — the tool image (1 session) · *enabler*

| | |
|---|---|
| **Files** | `docker/sast/Dockerfile`, `harness/sast/image.py` (mirrors `agent_image.py`: `ensure()` + tag cache via `docker_ops.image_exists`), `scripts/setup_sandbox.sh` gains an optional `--with-sast` build |
| **Contents** | Debian + rust stable (clippy, rustfmt) · **OpenGrep v1.26.0** (no official image — upstream `install.sh` or a release binary, **checksum-pinned**) · **ast-grep v0.45.0** (`cargo install ast-grep --locked`; invoke `ast-grep`, the `sg` alias is deprecated) · `clippy-sarif` + `sarif-fmt` · `cargo-geiger` · `cargo-audit` · `dylint` + `dylint-link` · `jq`. Pin every version **by digest or checksum** — the image digest is half the score key (§8.3) |
| **Contract** | `run_sast(image, clone_dir, rules_dir, cargo_home) -> Path(sarif_dir)`; mounts `/src:ro`, `/rules:ro`, `/cargo:ro`, writes only to a tmpfs `/out`; `--network none`; gVisor runtime; `--offline` for every cargo invocation |
| **Prefetch** | orchestrator-side `cargo fetch --locked` into a per-target cargo home (downloads, does **not** build → no `build.rs` executes on the host) |
| **Acceptance** | `vuln-pipeline sast --smoke` runs all Tier-P + Tier-C tools over `targets/rust-canary/crate` inside the container, emits ≥1 SARIF file per engine, `docker inspect` confirms `runtime=runsc` and `NetworkMode=none`, and the run manifest records `image_digest` |
| **Stop if** | Tier-C cannot run offline after prefetch (then Tier-C moves to the target image and the plan gets a fork; Tier-P is unaffected) |

### P1 — the corpus (1 session) · *W29, the prerequisite for every number*

| | |
|---|---|
| **Files** | `corpus/pins.jsonl`, `corpus/findings.jsonl`, `corpus/suppressions.jsonl` (empty), `harness/sast/corpus.py` (clone cache keyed `(repo, commit)`, same shape as `novelty.py`'s) |
| **Extraction** | pins ← `targets/*/THREAT_MODEL.md` **Pin:** line + `targets/*/config.yaml`; findings ← the internal disclosures ledger joined with each `*-disclosure/`, `*-pr/` REPORT for `file:line` + mechanism; **refuted** candidates ← `targets/*/JOURNAL.md`, `BACKLOG-VERDICTS-*.md`, `scratchpad/.../VERDICTS.md` |
| **Acceptance** | every confirmed finding resolves to a real `file:line` **at its pinned commit** (verify by checkout, not by trust); ≥15 refuted/contested rows present — a corpus with only confirmed findings cannot score a rule's negatives |
| **Stop if** | fewer than ~10 findings survive the `file:line`-at-pin check — then the corpus needs manual repair before anything downstream is meaningful |

### P2 — experiment E1 (1 session) · *W31, the falsifier* — **decision gate**

| | |
|---|---|
| **Input** | 6–8 hand-written rules: 3 enumerators (validation-predicate + call sites; N-ary sink arms; unit boundaries) and 4–5 candidate rules (counter-width overflow; alloc-from-parsed-length; recursion-without-depth-cap; value-range bound) |
| **Run** | P0's image over P1's pinned clones of h2, hyper, rustls, quick-xml, lopdf, object |
| **Measure** | **(0) does OpenGrep's Rust taint mode actually work** — the one unverified capability the design leans on (§3); run one taint rule with a known source→sink pair in a corpus crate before trusting any taint result · (1) U2 recall vs our own confirmed findings · (2) U1 completeness — sites the mirror-walk used, **and the residue it never visited** · (3) hits/kloc pre- and post-structural-filter |
| **Acceptance** | the three numbers are written to `docs/case-studies/E1-sast-retro.md` — including the negative results |
| **Decision** | **positive residue in (2) → build P3+.** Clean negative in (1) is expected and fine. **No residue in (2) → stop here** and keep only U3/U4 (rules as memory), skipping the whole scan spine. Publishing that negative is a real result, not a failure |

### P3 — the spine (1–2 sessions)

| | |
|---|---|
| **Files** | `harness/sast/{normalize,cluster,filter,runner}.py`; `.claude/skills/sast-scan/SKILL.md` (+ `.agents` twin); `vuln-pipeline sast` in `cli.py` |
| **Order** | `normalize` (SARIF→`Hit`) → `cluster` (`Hit`→`Cell`) → `filter` tiers 1–3 (all free) → tier 4 agent judge, one per cell, emitting `where_checked` |
| **Wiring** | `capabilities.py::_GATES` gains rule-pack rows; threat-model Step 1.5 stamps the emphasis pack; cells append to the finder brief as **additive** hints |
| **Acceptance** | on one real target: ≲20 cells from ≳300 raw hits, **every drop counted and logged by tier**, and `pytest` covers normalize/cluster/filter as pure functions (the `feedback.py` house style — pure decisions, unit-testable without containers) |
| **Stop if** | cells exceed ~40 after filtering — the filter chain is not carrying its weight and tuning it beats building the loop on top |

### P4 — the loop (2 sessions) · *W30* — **the proof-of-compounding gate**

| | |
|---|---|
| **Files** | `harness/sast/{distill,score,promote}.py`, `rules/META.jsonl`, `rules/tests/<rule-id>/{positive,negative}.md`, `feedback.py` edges **P8a/P8b/P8c** |
| **Order** | `rules score` first (it can score the P2 rules retroactively) → `promote` (the §6.4 gates) → `distill` (the agent-assisted seed→rule step) → `retro` |
| **Acceptance** | **one net-new candidate surfaces via retro-scan in a target we already finished, and survives the 3-skeptic verify.** That single event is the whole thesis; until it happens the loop is unproven |
| **Guardrail** | `promote` refuses any rule whose negatives do not pass — no override flag. A rule that cannot distinguish the guarded sibling from the unguarded one is a `grep`, and admitting one poisons every later score |

### P5 — depth (2+ sessions)

Dylint workspace with the three Rudra ports (panic-safety, higher-order invariant, Send/Sync
variance) — expensive per rule, justified only where a text matcher provably fails, which P2/P4 data
will show. `vuln-pipeline-sast-nightly` image for MIRAI/lockbud on the **shadow track**.
`/variant-scan --passes blind,tm,cve,sast`. Suppressions wired into `/triage` next to `fp-rules.txt`.
**Acceptance:** a Dylint lint beats its text-rule twin on the same seed — that comparison is the
reason to pay the authoring cost, so run it before writing lints two and three.

### P6 — BYOL CodeQL (1 session, optional)

`/opt/codeql` mount detection + the triple-explicit activation (§10.2) + a `codeql-security-extended`
lens id in the union. **Acceptance:** an identical downstream artifact schema with and without CodeQL,
proven by diffing two runs' `Cell` output on the same target.

### Cross-cutting rules for every phase

- **Nothing bypasses verify.** No phase may add a path from a tool hit to a report line.
- **Every drop is counted.** A filter that silently truncates reads as "covered everything".
- **Pure decisions live in pure modules.** `filter`/`cluster`/`promote` follow `feedback.py`: the
  module owns the decision, the CLI owns the side effect — so gates are unit-testable without Docker.
- **Rule ids are permanent.** `RIP-R<nnn>` is cited in disclosures; never renumber, only deprecate.
- **The blind pass stays unseeded.** If its unique-finding rate drops after this lands, that is the
  regression to investigate first (§12).

### First vertical slice — if only one session is available

Build the image (P0), clone h2 at its pin, write **three** rules (one enumerator, one candidate, one
deliberately-broken rule that matches guarded and unguarded alike), run them through the container,
and hand-inspect the output. This exercises the image contract, the SARIF path, the rule-test
discipline, and the negative gate in one pass — and the deliberately-broken rule is the check that the
positive/negative test machinery actually rejects junk.

---

## 14. Provenance

Tool selection, FP budgets, and the family→tool→oracle map are from
the internal Rust static-analysis tooling reference (2026-07-20). The routing spine is **ADR-1**; the lens set is **W20–W27**; the "seed is a pattern from
any disposition" rule and the three seed sources are [`variant-analysis.md`](variant-analysis.md) /
`/variant-scan`; the five-number scoring schema and R1–R11 are `profiles/rust/fp-rules.txt`; the
capability gate is `harness/capabilities.py`; the shadow-vs-active two-track discipline and the
noise-gate are borrowed from the operator's WAAP rule-mining work. The diagnosis motivating U1 is
`LESSONS.md` **L51**.
