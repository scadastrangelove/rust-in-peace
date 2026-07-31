# Bring-up of the `sast-driven` mode — what the first real runs measured

**Date:** 2026-07-28 · **Host:** x86_64 box (12 cores, 62 GB) · **Image:** `vuln-pipeline-sast`
Design: [`../sast-layer.md`](../sast-layer.md) · Decision: [`../DECISIONS.md`](../DECISIONS.md) ADR-2

This records what building and first-running the layer actually produced — including the parts that
failed. It is the empirical companion to the design, and it exists because the design's own rule is
that a layer like this must be **falsifiable**, not asserted.

---

## 1. The headline measurement: Rust's "default rule pack" is nearly empty

Counted inside the built image:

| source | Rust rules out of the box |
|---|---|
| `semgrep/semgrep-rules` → `rust/lang/security/` | **10** (`.yml`) |
| `trailofbits/semgrep-rules` → `rs/` | **1** |
| **OpenGrep total for Rust** | **11** |
| clippy | **815** lints — 332 `default_allow` (opt-in), 416 `default_warn`, 67 `default_deny` |
| Dylint (trailofbits `general`) | **9** lint libraries |

The 11 pattern rules are shallow audit-tier checks — hard-coded crypto, disabled TLS verification,
`unsafe` presence, `temp-dir`, `args`. Nothing structural, nothing protocol-aware.

**This quantifies the reference document's "classic taint SAST is weak for Rust" headline**, and it
changes the plan in two concrete ways:

1. **OpenGrep's value is U3 (rules we write), not U2 (vendor defaults).** Rule authoring is not a
   "later, after pruning" phase for that engine — it is the only phase. Keep the 11 running (free),
   but expect no yield ledger signal from them.
2. **The pruning question narrows to clippy's opt-in tier** — those 332 `default_allow` lints are
   where the noise lives and the only population where "prune what doesn't pay" has real content.

A note on attribution: `clippy-driver -W help` publishes each lint's **default level** but *not* its
group (pedantic/nursery/restriction). The authoritative group table needs network we do not have at
run time. So hits are tagged `default_allow` / `default_warn` / `default_deny` and labelled as such —
that answers the actual question ("is the opt-in tier earning its noise?") without inventing a
taxonomy we cannot verify offline.

---

## 2. First run — httparse (4,107 non-test LOC)

| metric | value |
|---|---|
| raw hits | 2,408 |
| dropped: `test_code` | 1,617 (67 %) |
| dropped: `duplicate` | 258 |
| **kept** | **533** |
| hits / kLOC | **129.8** |
| **cells** | **12** |
| rules firing | 39 |
| by engine | clippy 416 · ast-grep 116 · geiger 1 |

Two readings, and they point in opposite directions:

- **Clustering works.** 2,408 hits → 12 cells is the whole cost argument: 12 agent judgments is
  affordable, 533 is not. The design's "stop if > 40 cells" tripwire was not hit.
- **130 hits/kLOC is very high** and is concentrated exactly where predicted:
  `clippy::unwrap_used` 125, `clippy::indexing_slicing` 73, `clippy::as_conversions` 42. On a byte
  parser whose indexing is bounds-proven by construction, most of these are the R1/R6 false-positive
  classes `profiles/rust/fp-rules.txt` already names. **This is the population the prune ledger
  exists to rank** — not a surprise, a measurement.

The **U1 enumerators fire as designed**: `rip-e004-index-or-slice` returned 69 sites,
`rip-e003-numeric-cast` 41. That is a worklist, not an alert, and completeness is its success
criterion.

---

## 3. Five infrastructure defects the first run exposed

Recorded because each was invisible to inspection and only a real run surfaced them — the same
reason the design insists a tool hit is never trusted without a run behind it.

| # | defect | root cause | fix |
|---|---|---|---|
| 1 | OpenGrep died on 2 of 3 rule packs | its bundled Python falls back to the **ASCII codec** with no UTF-8 locale in the container, then throws `UnicodeDecodeError` on any rule file containing an em-dash | `LANG/LC_ALL=C.UTF-8`, `PYTHONUTF8=1` |
| 2 | every OpenGrep primary invocation `rc=2` | `--metrics` **does not exist** in OpenGrep — the fork stripped semgrep's telemetry entirely, so there is nothing to opt out of | drop the flag |
| 3 | ast-grep reported `empty` despite 87 KB of output | status was evaluated **before** a post-hoc `cp` from stdout | redirect inside the command |
| 4 | Dylint "prebuild failed" in the image | the build **succeeded**; the copy globbed the wrong directory — dylint emits `lib<name>@<toolchain>.so` into a **workspace-level** target dir, not the member's | locate by naming, not by assumed path |
| 5 | Dylint failed at run time, `--network none` | dylint compiles a **per-toolchain driver on first use**, which needs network | pre-build the driver during the networked *fetch* phase into the mounted cargo volume via `DYLINT_DRIVER_PATH` |
| 6 | Dylint *still* failed with the driver present — `could not find dylint_version` ×8 | a lint **workspace** builds one umbrella `.so` plus one per member, and **only the umbrella exports `dylint_version`**. Handing dylint the whole directory makes it abort on every member and lose the umbrella with them | select libraries by `nm -D` symbol export, not by naming convention (9 files → 1 loadable umbrella carrying all 9 lints) |
| 7 | every clippy hit tagged `unattributed` despite a "successful" catalogue | the v1 image shipped a catalogue containing **4** lints — a broken regex matched a couple of stray lines — and the regeneration guard only tested *emptiness*, which 4 lints passes | regenerate on a **plausibility floor** (clippy has ~800; under 100 is a parse failure), not on `!= 0`. Now 815 lints: 332 `default_allow`, 416 `default_warn`, 67 `default_deny` |
| **8** | **clippy silently TRUNCATED its scan on both large crates and reported `ok`** | two separate aborts — an unrelated *example* failing to compile (hyper's `hello-http2`) and `#![cfg_attr(test, deny(warnings))]` escalating our added `-W` lints into hard errors under `--all-targets` (h2). Reported clean because the invocation is a **pipe** (`cargo clippy \| clippy-sarif`) whose exit code is the *last* stage's — and `clippy-sarif` succeeds on truncated input. `pipefail` was set in the runner but does not cross an inner `sh -c` | `--cap-lints=warn`; drop `--all-targets` (tests/examples are filtered out downstream anyway); and a **truncation check** that greps the tool's own abort vocabulary and marks the engine `partial`, surfaced separately in `engines_partial` |

**Defect 8 is the one that mattered**, and it is why L52 exists. It produced a *confident wrong
number*: the 6× hits/kLOC spread between h2 (74) and hyper (11.8) looked like a property of the code
and had a plausible story attached (lint hygiene) — it actually measured **when each abort happened**.
A silent skip announces itself as a zero; a silent truncation announces itself as a plausible
measurement, which is far more dangerous. Batch 1's clippy counts are therefore reported below as
plumbing evidence only, not as data.

**What made these cheap to find:** the fallback-and-record discipline. Every engine tries a rich
invocation, falls back to a minimal one, and records *which variant ran* plus the stderr tail. Defect
2's exact message (`unknown option '--metrics'`) came straight out of `engines.jsonl` — no debugging
session required. A runner that had simply swallowed non-zero exits would have reported "clean" with
two of six engines silently dead, which is precisely the failure mode the "no silent skip" rule exists
to prevent.

Defects 3 and 4 are both the same species and worth naming: **a status field that reports on the
wrong artifact**. Neither tool was broken; both were working while the harness said otherwise. When
adding an engine, verify the artifact it actually wrote before believing the status.

---

## 4. Corpus batch — 7 crates, 238 kLOC

Two batches were run. **Batch 1 (v1.3) is void as data** — defect 8 truncated its clippy scans — but it
did its real job: it exposed the eight defects above. **Batch 2 (v1.4) is the valid one**, 7/7
complete, and is what this section reports.

| crate | kLOC | raw | kept | /kLOC | cells | rules | clippy scan |
|---|---|---|---|---|---|---|---|
| h2 | 25.8 | 2 176 | 1 801 | 69.9 | **47** | 76 | all-features |
| httparse | 4.1 | 370 | 336 | 81.8 | 12 | 34 | all-features |
| hyper | 21.9 | 384 | 258 | 11.8 | 34 | 23 | default (all-features `partial`) |
| lopdf | 21.4 | 2 433 | 1 985 | 93.0 | 27 | 71 | all-features |
| object | 70.5 | 5 355 | 4 292 | 60.9 | **56** | 69 | default (all-features `partial`) |
| quick-xml | 35.6 | 1 864 | 1 548 | 43.5 | 25 | 61 | all-features |
| rustls | 58.5 | 3 390 | 2 729 | 46.6 | **97** | 84 | default (all-features `partial`) |

**The truncation detector earned its keep immediately**: on hyper, rustls and object the
`--all-features` scan aborted and was marked `partial`, the fallback ran the default-feature scan to
completion, and `manifest.json` records both. Every crate has a *complete* clippy scan — but three of
them at default features, which is a coverage difference the ledger must not paper over. Batch 1 would
have reported all seven as clean.

How much batch 1 was off by: httparse `kept` 583 → 336, quick-xml 1 041 → **1 548** (it had been
truncated *upward*-looking by scanning test code), h2 1 917 → 1 801. The counts moved in both
directions, which is exactly why a truncated scan cannot be corrected after the fact.

By engine (kept, all crates): clippy 9 428 · ast-grep 3 085 · opengrep-tob-rs 133 · the rest small.

**Two results that matter:**

1. **The opt-in tier is the noise, definitively.** `default_allow` 9 791 vs `default_warn` 118 — the
   lints we turned on deliberately account for **98.8 %** of clippy's output. The prune question is
   well-targeted.
2. **The cell tripwire fires on the big crates.** rustls 97, object 56, h2 47 all exceed the design's
   "stop if > 40 cells" threshold. On protocol/large crates the structural filter is *not* carrying
   its weight, and triaging 97 cells by agent is the expensive failure the design exists to avoid.
   Tighten the filter before spending agent budget there.

### 4.1 The prune ledger splits the noise two ways

`prune_report.py` over batch 2's 7 crates (**12 949 hits, 136 rules firing**):

| class | hits | share | evidence bar |
|---|---|---|---|
| **non-security** | 5 890 | **45.5 %** | **droppable on inspection** — the category cannot express a security defect |
| security-relevant | 3 251 | 25.1 % | prune only on measured yield: ≥3 crates AND zero surviving candidates |
| enumerator (U1) | 3 085 | 23.8 % | judged on completeness, never pruned on volume |
| unclassified | 723 | 5.6 % | kept by default, listed for review |

**The first prune is semantic, not statistical.** `clippy::doc_markdown` (677 hits — missing backticks
in a doc comment) will never be a vulnerability no matter how many crates it fires on; the same goes
for `must_use_candidate` (866), `missing_const_for_fn` (801), `use_self` (769), `missing_errors_doc`
(675). Waiting for yield data on these wastes a triage cycle to learn something the category already
tells you. **40 % of the volume goes away today, with no triage at all.**

The other 31 % genuinely needs the yield evidence, and volume must not decide it:
`clippy::indexing_slicing` on a bounds-proven byte parser is noise; on a wire-parsed length field it
is the bug. That is precisely the distinction the ledger's hand-filled candidates/confirmed columns
exist to capture.

Two unclassified rules deserve promotion on review: `clippy::significant_drop_tightening` (lock-guard
lifetime — concurrency) and dylint's `non_local_effect_before_unhandled_error` (state mutated before
an error return — the panic-safety / broken-invariant class, and the only dylint rule with real
volume: 20 hits across 4 crates).

---

## 5. The first judge + finder pass — h2 @ `9416dc87`

The first time any cell reached an agent. Eight reachability judges (one per cell, after three cells
were dropped by the capability gate with recorded reasons), then finders on the cells that produced a
seed.

| cell | hits | reachability | seed |
|---|---|---|---|
| panic-surface | 202 | yes | **none** — mutex-poison cascade / proven bounds / operator-driven |
| conversion | 139 | yes | **none** — guarded upstream, or the value is not attacker-scaled |
| arithmetic | 123 | yes | weak — `framed_read.rs:338`, self-bounded by the CONTINUATION-flood limit |
| concurrency | 88 | **no** | none — zero `.await` in the subsystem |
| index-surface | 65 | **no** | none — 8/8 guarded |
| unclassified | 31 | yes | weak — `recv.rs:161` (`result_large_err`, ≥288-byte Err variant) |
| **unsafe** | **3** | yes | ✅ `hpack/header.rs:283` |
| **panic-safety** | **4** | yes | ✅ `prioritize.rs:818` + `stream.rs:307` |

### 5.1 The headline: cell volume is anti-correlated with yield

**The two smallest cells produced both real seeds. The five largest produced none.** 527 hits across
the top five yielded nothing; 7 hits across the bottom two yielded both leads. Ranking cells by hit
count — which is exactly what raw tool output invites — would have put the winners last.

The concrete consequence: **rank cells by class prior and by the crate's own advisory history, not by
volume.** For h2, all three past advisories were resource-exhaustion in `proto/streams/` accounting;
the 4-hit `panic-safety` cell sat precisely there.

### 5.2 Judge quality — the guards were traced, not assumed

The judges did not stop at "looks guarded":

- **index-surface**: the guard is *outside the crate* — `tokio_util::LengthDelimitedCodec` (built at
  `codec/mod.rs:44-50`) guarantees every frame buffer is ≥ `HEADER_LEN`. The judge verified this
  against tokio-util 0.7.15's own source, and separately confirmed `Cursor<&mut BytesMut>::chunk()
  .len() == remaining()` from bytes-1.10.1 to close the `decoder.rs:337` slice.
- **concurrency**: `grep .await` over `proto/streams/` + `connection.rs` returns **zero**. The
  subsystem is poll-based over `std::sync::Mutex`, structurally precluding the guard-across-await
  defect the lint hints at. The one peer-influenced loop under a lock is capped at
  `DEFAULT_LOCAL_RESET_COUNT_MAX = 1024` — the Rapid-Reset mitigation working as designed.
- **arithmetic**: established that the shipped artifact **wraps** rather than panics — no `[profile]`
  in `Cargo.toml`, and a library inherits the downstream binary's profile. That fact reclassifies any
  future arithmetic finding in this crate.

### 5.3 Three defects in our own tooling, found by the judges

1. **Class label conflated disjoint trust boundaries.** The `unsafe` cell merged
   `hpack/header.rs:283` (real `unsafe`, decode path) with two `hpack/table.rs` hits that contain no
   `unsafe` at all — and, decisively, `table.rs` is the **encoder** table on the *send* path, never
   reached from `framed_read.rs`. Judge's phrasing: *"same class name, disjoint trust boundary."*
   Clustering on `(class, module)` cannot see this; only reading the code can.
2. **Phantom rules from unknown lints.** `clippy::manual_assert_eq` does not exist — rustc emits
   E0602 "unknown lint", and the SARIF bridge turns that into a hit attributed to the nonexistent
   lint. Such rules can never fire meaningfully and can never be pruned on yield. Now filtered, with
   a `phantom_rule_unknown_lint` counter.
3. **`fixtures/` was not structurally excluded** — 39 gitleaks "generic-api-key" hits on h2's HPACK
   test vectors. Caught by hand at the capability gate; now a filter rule.

### 5.4 The naming trap, in both directions

Two rules were nearly misclassified, for the same reason and opposite outcomes:

- `missing_panics_doc` looked like documentation → it fires because clippy **proved the function can
  panic**. Nearly demoted; promoted to `primary`.
- `checked_conversions` looked like a missing check → it fires where a manual check **already
  exists** (it asks you to spell it differently). Its firing is evidence the check is *present*.
  Nearly kept; demoted to `corroborating` after the judge read both sites.

**A rule is named for its remedy, not its trigger.** When auditing a classifier, read what makes the
rule fire — never what it asks you to do about it.

### 5.5 Finder results

- **`hpack/header.rs:283` (`from_utf8_unchecked`) — SOUND.** Exhaustive construction audit: the
  private tuple field is written in exactly 4 places, all in `header.rs`; two constructors take
  `&str` (structurally valid), one runs `from_utf8(...)?` on the same binding it wraps with no
  intervening clone. No post-construction mutation exists — the whole `impl` is 5 methods, none
  mutating. Critically, the Huffman decoder emits arbitrary bytes (its own test round-trips
  `b"\xFF\xF8"`), and validation is correctly placed **after** decompression. A clean refutation with
  evidence, which is a valuable result, not a failure.
  *Defence-in-depth note (not a defect): the invariant holds by convention, not by the type system.*

- **`prioritize.rs:818` + `stream.rs:307` (release-stripped `debug_assert!` on a discarded
  `Result`) — REFUTED, dynamically.** The premise was "in release the `Err` is silently dropped".
  It never applies: `FlowControl::send_data` (`flow_control.rs:170-188`) guards the first
  `decrease_by` with a **hard `assert!`**, not a `debug_assert!` — a violated precondition *panics*,
  it does not return `Err`. The second `decrease_by` is unreachable because `prioritize.rs:811`
  (`assign_capacity`) runs immediately before, and at the stream site `len` is clamped at
  `prioritize.rs:787` to a snapshot of the same window taken at `:749`, with nothing mutating it in
  between. The `Result` is provably `Ok`, so removing the assert in release removes nothing.
  - **The maintainers said so in advance.** Commit `0189722` (PR #692): *"we check for
    over/underflow only with `debug_assert!`, assuming that those code paths do not over/underflow."*
    The lead was a rediscovery of a documented, reviewed decision.
  - **The scary comment was stale.** `send.rs`'s *"this decrement can underflow based on received
    frames!"* predates that same PR, which converted `-=` into a checked `decrease_by()?` mapped to a
    connection GOAWAY, with regression test `window_size_decremented_past_zero`. RFC 9113 §6.9.2 is
    modelled correctly (negative windows are representable; INITIAL_WINDOW_SIZE is correctly not
    applied to the connection window).
  - **Verified, not argued.** The finder instrumented a working copy, asserted the connection-level
    invariant at runtime across the full 201-test suite plus 300 adversarial rounds (1.7 M DATA
    frames / 1.27 GB) with no violation — and confirmed the probe itself works by making a
    deliberately over-strong variant fire immediately. It also string-searched the *built* rlibs:
    all 14 `debug_assert!(_res.is_ok())` absent from release, the hard `assert!` present.

### 5.6 Verdict on the h2 pass: **zero findings**

Both seeds refuted, one of them dynamically with a reusable adversarial harness. That is the honest
result, and it is **exactly what §11 predicted**: SAST does not find this layer's bugs. h2 is a
protocol/state-machine target, and every h2 finding this project has ever produced came from
invariant reasoning, not from a scanner.

What the pass did produce, and what it cost:

| | |
|---|---|
| findings | **0** |
| agent calls | 8 judges + 2 finders |
| tooling defects found | 3 (§5.3) — all now fixed |
| methodology results | 2 (§5.1 volume anti-correlation, §5.4 the naming trap) — both now encoded in the skill |
| reusable artifact | an adversarial h2 flow-control harness (`tests/h2-tests/tests/adversarial_flow.rs`) |
| latent observations | 4, none filed (e.g. `store.rs:144-172`'s release-stripped `debug_assert!(new_len == len - 1)`: safe at all 7 call sites today, fragile by construction) |

**The mode's justification cannot rest on h2.** It must come from either U1 enumeration completeness
(measurement (2) of E1 — still unrun) or from the parser targets (lopdf, quick-xml, object), which is
where ADR-1 predicts scanner-shaped bugs actually live. Running it against a protocol target first was
the right *test* precisely because it was the least favourable case.

One excursion, honestly reported as a non-finding: the harness did trip
`debug_assert!(self.slab.is_empty())` at `store.rs:231` — but it is `#[cfg(feature = "unstable")]`,
a `debug_assert!`, carries the comment *"In practice, we don't need to ensure this"*, and fired only
on connections the harness itself killed via h2's own PROTOCOL_ERROR GOAWAY. A benign-peer control
(3 000 rounds, 4.99 M DATA frames) was clean.

---

## 6. Round two — rules developed against ground truth instead of vendor defaults

The vendor-default approach (§4) was the wrong end of the problem: for Rust the vendor corpus is 11
shallow rules, so "run everything and prune" had nothing to prune *from*. Round two inverts it —
develop rules against a labelled target, gate them, then deploy.

**Ground truth:** DVRA's three implementations (`corpus/dvra-findings.jsonl`, 39 findings). dvra-1
labels at site level (`file` + `vuln_line` + `fixed_fn`, the hardened twin **in the same file**);
dvra-2/3 label at scenario level with `reproducer` commands but **no locations**. The corpus keeps
that distinction explicit rather than blurring oracle-given locations with ones we derived.

**The gate** (`scripts/rule_test.py`, `rules/rule-tests.yml`): positive (matches the planted line) ·
negative (does **not** match the hardened twin) · per-decoy expectations. The negative gate is the
one that matters — DVRA puts `fixed_handle` in the same file, so "matches the file" proves nothing.

### 6.1 Results

| corpus | hits | of which real |
|---|---|---|
| dvra-1 | 5 | 5/5 planted, zero leaks onto `fixed_handle` |
| dvra-2 | 2 | incl. a shell-spawn site |
| dvra-3 | 8 | **DVRA-002**, **DVRA-006**, **DVRA-008** — all three found without location labels |
| 12 real crates | **0** | — but see §6.3, this is not a precision result |

**DVRA-008 is the loop working**: a path-traversal rule developed on dvra-1 located
`destination.join(entry.path)` in dvra-3's bundle extractor — a scenario whose oracle gives an id and
a CWE but no file:line. The code's own doc comment confirms it.

### 6.2 Three mistakes, each caught only by a SECOND implementation

1. **FP-tuning produced a false negative on the class's canonical case.** After the rule fired on
   `Command::new("valgrind")` in rustls CI tooling, I constrained the program name to non-literals —
   "a literal program is safe". `Command::new("sh")` is the most dangerous literal there is. That
   blinded the rule to dvra-3's DVRA-002 *and* DVRA-006, and stayed invisible on dvra-1, whose
   `hooks.rs` builds its shell string with `format!("sh -c …")` and was still caught.
2. **A guard delegated to a helper defeats the guard-absence rule.** dvra-1 inlines its traversal
   check; dvra-3 calls `validate_relative_path(..)?`. The rule passed the negative gate on one and
   leaked on the other. The obvious patch — treat `validate_*`/`check_*` as a guard — was written and
   **reverted**: it suppresses on a NAME, not a behaviour, so a `validate_path` that validates the
   wrong thing would silence a real traversal forever.
3. **Merging shapes into one `any:` silently killed a branch.** ast-grep's `constraints:` is
   rule-level, so a metavariable left unbound by the matching branch still has its constraint
   evaluated — the computed-program shape stopped firing entirely while the rule still looked
   healthy. One shape per rule.

**Standing conclusion: in a candidate-generator pipeline, tune for RECALL.** A false positive costs
one agent read; a false negative is permanent and silent. Precision is carried downstream by the
reachability judge and the finder (ADR-2: a rule is never a verdict).

### 6.3 The zero that isn't a precision result

0 hits across 12 real crates — including five parser-heavy ones (image, png, ttf-parser,
miniz_oxide, ciborium) chosen precisely because they hold 28 of our own 58 findings — looks like a
clean precision number. **It is not. It is zero coverage.**

Measured: those six parser crates contain **35 `with_capacity` sites and zero `req.*` accessors** in
five of six. The alloc rule requires `req.header(..)` / `req.query_get(..)` in the enclosing function,
because that is what DVRA's upload handler looks like. A byte parser reads its lengths from a buffer,
not from a request. The rule is structurally incapable of firing on this code, and so is every other
rule in the set: no SQL, no credentials, no process spawning anywhere in a codec library.

**A rule inherits the SHAPE of the corpus it was developed on.** DVRA is web-application shaped, so
the rules are web-application shaped, so they are blind to the protocol/parser classes this project
actually hunts. That is not a flaw in DVRA — it is the wrong ground truth for our targets.

### 6.4 Our own findings are the right source, and are not yet usable

`scripts/build_rip_corpus.py` joins the internal disclosures ledger with the disclosure packages' `file:line`
citations. The result is sobering:

| | |
|---|---|
| findings | 58 across 23 crates |
| **with a derived site** | **11** — the internal disclosures ledger stores artifacts, not locations |
| **under embargo** (not merged/closed) | **53 of 58** |
| both pattern-shaped *and* located | **3** — all three embargoed |

So the classes we actually hunt have ground truth in principle and not in practice. Making it usable
means extracting sites from GHSA texts and campaign JOURNALs, and triaging which of the 24
pattern-shaped candidates a rule could express at all — most are protocol logic that no pattern can.

**Disclosure-safety note:** the derived corpus carries `file:line` for unfixed defects plus private
advisory URLs, in a public repository. It is gitignored under the same fail-closed rule as the
disclosure packages. The hygiene check did not catch it — the check knows the package paths, not this
new one. The DVRA corpus stays tracked: that target is deliberately vulnerable and published as such.

---

## 7. Honest gaps at bring-up

- **No gVisor on this host.** The analyze phase compiles the target and therefore executes its
  `build.rs` and proc-macros. It runs with `--network none`, and the run records
  `sandbox: docker-default` rather than implying otherwise. Acceptable for well-known crates; install
  `runsc` before pointing this at anything unvetted.
- **The OpenGrep Rust *taint* path is still unexercised** — the 11 vendor rules are pattern rules.
  Whether `--taint-intrafile` performs on Rust remains the design's open question (§12), and it needs
  a rule of our own to answer.
- **No candidate has been produced yet**, let alone verified. Everything above is volume and
  plumbing. The mode's actual claim — that it finds something the other three passes do not — is
  unmeasured until the batch runs and its cells go through the reachability judge and a finder.
