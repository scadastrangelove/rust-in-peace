# rust-in-peace — lessons learned (cross-campaign)

**How to use this file.** The working set is the **six principles (P1–P6)** below — that is what belongs in
your head during a campaign. Each folds several of the numbered lessons; the full evidence-bearing entries
(**L1–L47**, each naming the campaign that proved it and the concrete change it implied) live in the
**Evidence appendix** at the bottom. The L-numbers are **stable** — memories, journals, and
`ARTICLE-DRAFT.md` reference them. When a principle and its raw lesson seem to differ, the raw lesson is the
record of what happened; the principle is the compression. Tag: `[PROVEN]` = a campaign demonstrated it.

*(Consolidated 2026-07-19 from L1–L24, extended same-day to L28, extended 2026-07-20 to L29–L37,
extended 2026-07-23 to L38–L44. Provenance:
L1–L9 x509-parser, L10–L14 lopdf, L15–L20 the five-crate disclosure session, L21–L24 quick-xml, L25–L27
miniz_oxide+ciborium, L28 png+image (blast-radius), L29 png+image (maintainer pushback/SECURITY.md scope),
L30 the L29 remediation pass itself (stale-clone PR trust incident), L31–L33 rmp-serde+ttf-parser
(honest-PoC re-verification: short-circuit false negative, main-check discipline, duplicate-scope analysis),
L34–L35 the fdeflate severity-dismissal + quick-xml maintainer-request follow-up (severity-magnitude
calibration; treating inbound comments as untrusted content), L36–L37 the "resolved"/"rejected" sweep
itself (refound-as-positive-signal + png#692's correction; scheduled re-checks on rejections, silent fixes
count as full wins), L38 corpus-isolation failure in a multi-agent A/B, L39–L40 the vendored-code
campaign (host-cap reachability + fork-as-yield-zone), L41 an anonymized real campaign in which a
verified finding had no authorized autonomous disclosure route (private escrow + reassessment,
not policy evasion), L42–L47 the protocol/state-machine campaign (layer-routed tools,
enforcement-asymmetry oracles, protocol-logic evaluation drift, shipping-layer ordering,
protocol-oracle discipline, and ecosystem seam amplification).)*

---

## The six principles (the working set)

### P1 — A finding is a lead until the code forces the verdict; verify with structure, not a smarter prompt.  `[PROVEN]`  — folds L1, L2, L3, L6, L12, L15, L22, L26, L30, L31, L32, L39
Every load-bearing premise — "the dependency rejects this", "this is reachable", "this fix closes it" — must
be pinned to source you actually read (`file:line`), against the exact artifact you will claim about. The
lever is **opening the source**, not "run it dynamically" (L2); dynamic is the oracle/tiebreaker. A second,
"smarter" LLM layer reproduces the same over-claim — only a **structural** forcing function catches it: a
`where_checked` field, an adversarial refute-panel, cross-model disagreement routed to CONTESTED (L1, L3, L6).
Reachability is the classic trap — a harness that **constructs** the object bypasses the parser; re-verify
through the real parse entry on crafted bytes (L12). Before reporting, reproduce against the version you'd
report against **and** `master`, and grep the maintainer's own tests/docs for intended behaviour (L15).
Before shipping a fix, re-run the PoC for **every** facet of the bug, not just the one that fired first (L22).
The same discipline extends to agent-built **fixes**, not just finds: build your own PoC as a path-dependency
against the fix branch (not the agent's own tests) and re-run the full suite yourself, then sweep for missed
siblings of the same pattern before calling the fix — and the disclosure — done (L26). A first PoC attempt
can itself under-claim: if the recursive call site you're exploiting propagates a `?`/early-return, a
naive cyclic construction silently short-circuits and reads as "safe" when it isn't — read the control flow
before trusting a negative result (L31). And "reproduce against `master`" (L15) has to fire on its own, not
wait for someone to ask "did you check main?" (L32).
- **Do:** cite-or-it-didn't-happen; verify against the real target + real entry point (unprompted, every time); make the check structural, never a better prompt; verify agent-built fixes the same way, then sweep for siblings; distrust a too-easy negative PoC result until you've read the recursive control flow.

### P2 — The detector's build profile is part of the threat model.  `[PROVEN]`  — folds L10, L24
Grade every crash against the target's **shipping** profile, not the instrumented one. An `overflow-checks`
panic that wraps silently in release is `overflow-checks-gated / R7` — downgrade it (L10). But R7 is the
**floor, not the ceiling**: investigate what the release build does *instead* of the gated crash — the same
root cause can silently corrupt state (quick-xml's namespace misresolution), which is worse *because* it's
silent (L24). "R7, move on" is exactly the reflex that misses it.
- **Do:** re-test under the shipping profile; label the gated crash R7 **and** chase what the ungated build does instead.

### P3 — Recall-first search, paid back by adversarial verification.  `[PROVEN]`  — folds L4, L5, L8, L18, L19, L21, L25, L40
Over-including in find is correct — the failure mode is triage, not recall. Route the search: capability-gate
the byte-crash track (blind on logic-heavy targets, L4); do the **threat model first** to classify the target
(fresh decoder → memory; hardened parser → resource-exhaustion / parser-differential) and pick the lenses
(L18). Run **both** blind and threat-model-seeded lenses — different strengths, arbitrated by the same skeptic
panel (L21). A second, independent 2-crate campaign sharpened this: all three pass-types (TM/CVE-seeded/
blind) can independently **converge** on the same headline bug (a strong confidence signal on its own), but
which pass-type yields the *most* on a given target isn't fixed — an unscoped blind sweep out-yielded a
seemingly-thorough threat model on one target's implementation-level bugs, while CVE-seeded's narrow-but-real
contribution was catching a known-CVE-shaped bug class plus acting as a version-fidelity tripwire (L25). Then
report **verdicts, not counts** (L8), and let a genuinely clean target be a valid `0` (L19). Watch the finder
failure mode: agents rabbit-hole in binary reverse-engineering (L5).
- **Do:** recall-first + route by capabilities/threat-model + blind∪TM∪CVE-seeded lenses → one adversarial panel → verdicts, not counts; don't let a good threat model replace the blind sweep, it may out-yield it.

### P4 — Static and empirical validation are complementary; route the oracle by target layer.  `[PROVEN]`  — folds L11, L14, L19, L42, L43, L47
Every serious static candidate needs an empirical validation stage, but **dynamic does not mean
byte-fuzzing by default**. For data-format parsers with a crash/OOB/alloc oracle, run seeded fuzzing
from both the corpus and static findings, and auto-escalate to a harness (L11). Deep structural parser
bugs still need targeted PoCs because mutation is shallow/high-volume (L14). For protocol/state-machine
targets, use a valid-state **control-vs-attack, spec-vs-impl, or invariant-symmetry differential**;
for API-contract targets, use a contract differential (L42–L43). A clean result under one oracle
only clears the class that oracle covers (L19). For ecosystem protocol crates, also validate the
**consumer seam**, not just the core crate: a safe shipping integration can neutralize the bug for its
users, while direct consumers and forks can re-expose the same default across the ecosystem (L47).
- **Do:** require empirical evidence, then select parser→fuzz, protocol→stateful/differential, or contract→spec/control differential; never turn one clean oracle into “target safe.”

### P5 — Disclosure is a first-class output; match the artifact to the target, the fix, and the sender's authority.  `[PROVEN]`  — folds L9, L13, L16, L17, L23, L27, L29, L33, L34, L36, L37, L41
Responsible disclosure is a deliverable, not an afterthought (L9). Gate it with an **adversarial
maintainer-eye review** — one skeptic tasked to reject / downgrade / wontfix — which right-sizes severity,
hardens reachability, and catches bad fixes before the maintainer does (L13). Match the artifact to the fix's
shape: a clean fix → **issue + PR**; a judgment call → **issue only, PR offered**; either way a self-contained
reproducer that **compiles against `master`** is the report (L17). When a lead is already handled, read *why*
— the fixing commit's stated limitations are a discovery vector (L16); and when the tracker already has your
**symptom**, that's a scoping question, not an auto-drop — compare root cause / attack model / affected path /
fix shape and file cross-referenced if yours is distinct (L23). **Channel default (2026-07-19):** for a repo
with no dedicated security-reporting channel (no SECURITY.md, no GitHub private vuln reporting), go
**public issue+PR by default** rather than cold private email — object/gimli/quick-xml went straight to
public and worked cleanly, while x509-parser's and lopdf's private emails sat unanswered a day+ before
being converted to public issue+PR anyway. Reserve private email for a repo that documents an actual
channel (SECURITY.md, a listed security contact, private reporting enabled). **Check it via the API, not just
`find -iname SECURITY*`**: `gh api repos/{owner}/{repo}/private-vulnerability-reporting` gave an authoritative
`enabled: true/false` for ciborium/miniz_oxide where SECURITY.md's absence alone would have missed that
ciborium actually has it enabled (L27). But a **present** SECURITY.md is the stronger signal, and the API
boolean doesn't substitute for reading it: image-rs's SECURITY.md explicitly scopes crashes/panics and
OOM/DoS **out** of their vulnerability program, and fanning out report-only issues framed as security
findings anyway (Severity/Impact language, no fix, no PR) drew a public maintainer rebuke for SNR and
rudeness — read the full text before filing, not just the private-reporting toggle, and don't fan out
report-only issues on a volunteer team (L29). L23's "cross-reference, don't drop" needs one more step
in practice: a matching closed issue's title tells you it was fixed, not what the fix actually covers —
pull the closing commit/PR and read its diff before deciding a finding is a duplicate, since the merged
fix can (and, twice in one campaign, did) have a narrower scope than the symptom it closed (L33).
Finally, a technically valid finding does not authorize its finder to send it: when project policy
requires human-authored communication and no human or opt-in coordinator is available, preserve the
case in private escrow and reassess it instead of manufacturing eligibility through another channel
or waiting for the risk to worsen (L41).
- **Do:** adversarial-review → compiling repro vs master → artifact matched to the fix → cross-reference (don't blind-drop) the known, reading the closing commit/PR's actual diff, not just its title or state → check `private-vulnerability-reporting` via API **and read SECURITY.md's declared scope in full** → require both channel eligibility and sender authority before any outbound action → public issue+PR only if that confirms no private channel and the bug class is in scope → don't fan out unfixed report-only issues.

### P6 — Dogfood the tool, and treat its own trust boundary as first-class.  `[PROVEN]`  — folds L7, L20, L28, L35, L38, L44
Periodically run the pipeline **on itself**: a security tool that executes untrusted target code and runs an
LLM over untrusted source is a first-class target — doing so found the crown jewel, the model-API credential
in the env of the exec container (L20). Prefer the **curated read-only** track (the autonomous byte track
trips cyber-safeguards; read-only doesn't, L7). And verify a proposed mitigation's cost *and* efficacy by
reading the code — don't ship a "fix" that doesn't actually split the trust boundary (L20). The trust-boundary
concern isn't only adversarial-input-shaped: a **cooperative, well-meaning fix-agent** with broad Bash access
in a parallel-agent run can itself blow the blast radius past its own task — one agent's unprompted "let me
repair my broken toolchain" took down `cargo`/`rustc` for every other concurrently-running agent sharing the
same host (L28). Environment/dependency repair for shared system tooling is the orchestrator's call, not an
in-task agent decision.
- **Do:** dogfood on a schedule; prefer read-only tracks; prove the mitigation actually mitigates; scope
  fix-agents to their own worktree and forbid autonomous repair of shared host/toolchain state.

---

## Evidence appendix — raw lessons (L1–L47)

*The numbered record, kept verbatim: each entry names the campaign that proved it and the concrete change it
implied. The six principles above are the compression; these are the evidence, and the numbers are stable
cross-reference targets.*

## x509-parser era (L1–L9) — summary

- **L1 — Cite the dependency.** Any claim about a *dependency's* accept/reject/parse behaviour must
  cite that dep's source `file:line`; an uncited dep-behaviour claim is inadmissible as the
  load-bearing premise of a `real` **or** a `false_positive`. (The one wrong x509 verdict rested on an
  uncited, false claim about `asn1-rs`.) `[PROVEN]` · cheap-win.
- **L2 — The lever is opening the dependency, not "run it dynamically."** Static-vs-dynamic wasn't the
  differentiator; whether the agent read the dep source was. Dynamic is the oracle/tiebreaker. `[PROVEN]`
- **L3 — A "smarter" review layer is not self-correcting.** The curator reproduced the same
  reachability over-claim; only outside pressure caught it. Need a structural forcing function
  (premise → where-checked field + adversarial reviewer). `[PROVEN]`
- **L4 — Route by target shape.** The byte-crash track is blind on logic-heavy targets; gate it on
  `capabilities.json`. `[PROVEN]`
- **L5** find agents rabbit-hole in binary reverse-engineering. **L6** cross-model disagreement is
  signal → CONTESTED at triage. **L7** the autonomous track trips Anthropic cyber-safeguards; curated
  read-only doesn't. **L8** report verdicts, not counts. **L9** make responsible disclosure a
  first-class output.
- **Don't-change:** recall-first finders over-including is correct (failure was triage, not find); the
  R1–R11 / CONTESTED taxonomy held; **in-image offline `cargo` verification (zero quota) is the
  highest-ROI tool** — institutionalize it.

---

## lopdf era (L10–L14)

### L10 — The detector's build flags are part of the threat model  `[PROVEN]` · medium
The crash pipeline built the target with `overflow-checks=on`. **All 5 autonomous "crashes" (both
models) were `panic_const_*_overflow` that do NOT reproduce under the target's shipping release
profile** (overflow-checks off) — they wrap silently (R7). The grader re-ran each PoC against the
*same* instrumented binary, so it graded build-config artifacts as `real`. Meanwhile the curated
static triage correctly called them overflow-checks-conditional — **the human-in-the-loop was more
honest on severity than the autonomous grader.**
- **Change:** re-test every crash against the target's *real release profile* before grading `real`;
  if it doesn't reproduce there, label `overflow-checks-gated / R7` and downgrade. Build the detector
  with the shipping profile, or add a shipping-profile re-test to the grade stage.

### L11 — Make coverage-guided fuzzing a first-class, always-run stage — seeded from statics too  `[PROVEN]` · medium
Across **both** campaigns, Miri / ASan / cargo-fuzz and the `reattack` find→fuzz bridge were **never
run end-to-end**, even on x509 where all three were installed. The dynamic stage is gated behind a
Track A crash (which may not exist) or an operator choosing to run it, and the find skill never
self-escalates to cargo-fuzz (on x509 it hand-crafted inputs for 93 min and never wrote a harness,
though `fuzzing.md`'s staircase prescribes it). Empirically, once run: a seeded `content_decode` fuzz
**rediscovered the real inline-image bug in ~2 minutes**, and the reattack bridge auto-reproduced 3/4
static findings.
- **Change:** the dynamic-fuzz stage should be **always-run**, seeded from the corpus **and** the
  static findings (B→fuzz), not gated on a crash. The find skill should **auto-escalate to writing a
  cargo-fuzz harness** after N tool-calls without a candidate input (enforce the staircase, don't just
  document it). Run the fuzz build with the shipping profile (L10).

### L12 — A bridge/harness "reproduction" is not automatically parse-reachable  `[PROVEN]` · cheap-win
The reattack bridge "reproduced" the `document.rs:779` panic by **constructing the Document via the
builder API, bypassing the parser entirely** — exactly the false-reachability trap that sank the x509
RSA finding (L1/L2), now recurring one layer up **inside the automated bridge**. "Reproduced via
construction" ≠ "reachable from untrusted bytes." (Here the finding *was* separately parse-reachable —
a real 487-byte PDF through `load_mem` — but only because that was checked by hand.)
- **Change:** any generated harness that builds the target object directly must be **re-verified
  through the real parse entry** (e.g. `load_mem` on crafted bytes) before the finding is called
  reachable. Flag construction-based harnesses in the scorecard.

### L13 — Adversarial "maintainer-eye" review is a cheap, high-value pre-disclosure stage  `[PROVEN]` · cheap-win
Before sending anything, one skeptical-maintainer agent per finding — tasked to **reject / downgrade /
wontfix** — was run. On the 4 lopdf findings it: **corrected severity (Moderate → Low on all four)**,
**caught a wrong fix snippet** (#1's `.ok().and_then` left a variable undefined; the right fix was a
one-token `?`), and **killed two would-be maintainer dismissals using the crate's OWN code**
(`max_decompressed_size` doesn't cover the `/W` vectors; `PageTreeIter` already caps depth at 256 → the
recursion bug is an inconsistency, not by-design). It also re-confirmed a reachability that would
otherwise have been rejectable.
- **Change:** make an adversarial maintainer-review a standard stage between "confirmed finding" and
  "disclosure" — it right-sizes severity, hardens the reachability argument, and catches bad fixes
  before they embarrass you in front of the maintainer.

### L14 — Fuzzing and targeted PoCs are complementary, not substitutes  `[PROVEN]` · principle
Coverage-guided fuzzing found the shallow bug (#1) in ~2 min but **structurally cannot reach
deep-structural bugs**: the recursion stack-overflow needs a ~10⁵-deep `/Pages` chain, and the
empty-`/ColorSpace` OOB needs a specific nested image-XObject structure — neither is synthesizable from
a seed corpus (both soaks ran millions of execs and found neither). Both were confirmed by **targeted
hand PoCs** derived from the static findings.
- **Change:** don't read a clean fuzz run as "no bugs" on structure-heavy targets. Pair fuzzing (shallow,
  high-volume) with targeted PoCs (deep, structure-aware) built from the static findings; report which
  surface each result covers.

---

## disclosure & hardened-target era (L15–L20)

Distilled from a session of five real-OSS campaigns (zune-jpeg, object, httparse, gimli) + a dogfood
self-review. These are about **what survives contact with a security-conscious maintainer**, and how a
hardened, heavily-fuzzed target behaves differently from a fresh one. Six real disclosures came out of it
(zune-jpeg YCCK panic — acked "will fix"; object zstd cap-bypass #951 + exports-trie exponential #953;
gimli quadratic DIE-attrs #898), and — just as important — several convincing-looking findings were
correctly **killed before reporting**.

### L15 — Verify against the ACTUAL target (release AND master) + the maintainer's own tests/docs, before reporting  `[PROVEN]` · principle
The finder agents produce *leads*, not verdicts. Every finding that looked real was re-checked against the
version we'd actually report against, and repeatedly disqualified there:
- **object exports-trie cyclic infinite loop** — real in the 0.39.1 *release*, but **already fixed on
  `main`** (PR #940, an ancestor-offset check the maintainer added days earlier). Building + running the
  PoC against a fresh `git clone` of `main` caught it before an embarrassing "you already fixed this."
- **gimli DWARF-expression backward-branch infinite loop** — real, but `set_max_iterations` is **documented**
  "to avoid denial of service attacks by bad DWARF bytecode" → a documented *caller* responsibility, not a
  gimli bug.
- **httparse bare-LF request-splitting** — looked like textbook smuggling, but is **tested** (`test_request_newlines`
  parses all-bare-LF successfully) + **in a doc example** + **RFC-9112-permitted** (recipient MAY) → intentional.
- **Change:** the report gate is not "an agent found it" but "it reproduces on the version I'd report
  against, AND it is not already fixed on master / documented as caller-responsibility / asserted by the
  maintainer's own tests as intended." Clone master, build, run the PoC there; grep the crate's tests +
  the API docs for the exact behaviour. This is L1/L3 ("cite the dependency", "smarter review isn't
  self-correcting") aimed at the *upstream* target instead of a dependency.
- **Addendum (httparse, second pass, 2026-07-19):** the checklist applies even when *I* do the manual
  PoC myself, not just when triaging a finder-agent's claim. Reproduced a raw-CRLF-in-folded-header-value
  behavior, called it "confirmed, a second distinct finding" on the strength of the PoC alone — then found
  the crate's own doc comment for that flag asserts *exactly* that value (`b"hello\r\n there"`) as the
  documented, intended contract, explicitly warning callers to normalize it themselves (same shape as the
  bare-LF case, just missed on the first pass). A parallel blind run's verify panel caught the doc line
  before I did. **"I reproduced it" is necessary but not sufficient — the docs/tests check is not optional
  just because a human, not an agent, is doing the verifying.**

### L16 — "Why is this already fixed?" is a discovery vector  `[PROVEN]` · principle
When object's cyclic-trie loop turned out fixed-on-master (L15), reading *why* (PR #940) surfaced the
maintainer's own comment: the fix "does not check for shared subtrees." Testing that acknowledged-but-open
gap produced a **genuinely new bug** — a 330-byte Mach-O with a shared-subtree trie → 2⁴⁰ traversals (an
exponential-time DoS), live on master → issue #952 + PR #953 with a verified fix.
- **Change:** when a lead is already handled, don't just drop it — read the fixing commit/PR for the
  maintainer's *own stated limitations*; "the acknowledged gap, now with a concrete PoC" is high-value and
  welcome.

### L17 — Match the disclosure artifact to the fix's shape; a compiling reproducer is the report  `[PROVEN]` · cheap-win
- A **clean, obvious fix** (object zstd cap-bypass: bound the `read_to_end` with `.take(size+1)`; the
  exports-trie: a traversal budget) ships as **issue + PR** — the PR is the fastest path to a merge.
- A fix that's a **judgment call** (gimli's quadratic attribute parse: cap vs. a new `set_max_attributes`
  API vs. docs — zero-byte forms are legitimate) ships as an **issue only, with the PR offered** — don't
  push a design decision the maintainer should own.
- Either way, the **self-contained reproducer that the maintainer can `cargo run`** — and which you
  verified compiles + reproduces against `master` — is worth more than any prose. Verify it builds before
  posting to a serious team.

### L18 — Threat-model-first predicts the surface CLASS and sets honest expectations  `[PROVEN]` · principle
Doing the 9-section threat model as stage 0 (the operator insisted, twice) paid off: it classifies the
target before any find runs. A **fresh decoder** (zune-jpeg: unsafe SIMD, arithmetic) → memory-corruption
is the priority (T1), and the run found the YCCK panic + confirmed the memory class matters. A **hardened,
heavily-fuzzed parser** (object, gimli, httparse) → the TM predicts memory bugs are *near-refuted by
design* and points at **resource-exhaustion / parser-differential** as the real surface — which is exactly
where every reportable finding came from. The TM's "fresh vs. hardened?" call routes the find lenses and
right-sizes expectations.
- **Change:** always do the threat model first; explicitly classify the target (fresh vs. hardened/fuzzed,
  safe-Rust vs. unsafe) and let that pick the priority threat class + the find lenses.

### L19 — On hardened targets the reportable finds are STATIC/differential; a clean target yielding 0 is a valid result  `[PROVEN]` · principle
Reinforces L14 with four data points. On a heavily-fuzzed crate, a fresh 1-hour ASan fuzz almost always
just **confirms "memory-clean"** (object: 175 artifacts = one by-design count-alloc class; httparse: 0/0/0
over 624M execs; gimli: 0/0/0 over 547M execs) — while the **reportable** bugs come from static + a targeted
PoC the fuzzer can't synthesize (object zstd cap-bypass, gimli quadratic DIE-attrs, the exports-trie
exponential). And **httparse yielded 0 reportable findings** after honest triage — a *valid, valuable*
outcome, not a failure. Do not manufacture a finding to "have something."
- **Change:** budget the fuzz as the memory-clean confirmer + the discovery of the static-find's dynamic
  twin; put the reportable-finding weight on static + targeted PoC; and let a genuinely clean target be
  clean (x509-style honest negative).

### L20 — Dogfood the pipeline on itself; and when the cheap fix doesn't exist, say so  `[PROVEN]` · principle
Running the find pass on the harness itself (inverted trust boundary: the *input* — target source + binary
— is adversarial, the *processor* is our own orchestration + an LLM over untrusted source) found the exact
crown jewel the self-threat-model flagged: **the model-API credential sits in the env of the container that
executes untrusted target code** (F1, the agent runs the binary via its own in-container shell) — plus a
**gVisor bypass I had just introduced** in the P0.3 soak script (runc + root + writable mount). And when the
"cheap interim fix" (run the binary in a separate token-free container) was proposed, *reading the code*
showed it isn't cheap — the token-container IS the exec-container; the honest answer was "no cheap split,
the real fix is a credential-injecting proxy," not a fake one.
- **Change:** periodically run the pipeline on itself; treat a security tool that runs untrusted code + an
  LLM over untrusted source as a first-class target. And verify a proposed fix's cost by reading the code —
  don't ship a mitigation that doesn't actually mitigate.

### L21 — "By the book" (threat-model-first) and "blind" find have DIFFERENT strengths — run both  `[PROVEN]` · principle
A controlled A/B on quick-xml (0.41.0) settled the "is the 9-section threat model worth it?" question with
data. Same target, same 3-skeptic verify panel, retry-resilient; only the finders differed — **Run A** = 5
identical generic "find memory/DoS/logic bugs" prompts (no TM); **Run B** = 5 surface-specific lenses (T1–T5)
seeded from the TM. Result: **neither dominates.**
- **Both found both "big" bugs** (the u16 `nesting_level` overflow and the serde-recursion stack overflow).
  For obvious-shaped defects the threat model is *not required* — a blind sweep trips over them too.
- **TM-first won on depth & the differential/logic surface.** It rated the serde bug HIGH with the exact
  recursion cycle (blind: MEDIUM, "class-level, not run"), and it *uniquely* covered the **parser-differential**
  class (namespace duplicate-binding / signature-wrapping, `<`-in-AttValue) — a surface a "find memory bugs /
  panics" prompt never looks at, because the TM had named trust-boundary integrity a priority *asset* and a
  whole finder was pointed there. This is the L18 mechanism in action.
- **Blind won on breadth for classes the TM under-weighted.** Only the generic run found the unbounded-alloc
  on an unterminated token — the TM's exhaustion lens was scoped to entity-expansion/escape and missed it.
- **TM-first = higher recall + higher raw-false rate** (9 candidates, **5 refuted** by the panel) vs blind
  (4 candidates, 0 refuted). Surface-specific lenses generate more — including weak — candidates; that is
  *safe only because* the shared adversarial verify gate is there to pay the false-rate back. The TM's
  negative predictions also held (T1 escape-unsafe refuted 0-0, as "memory near-refuted by design" foretold).
- **Change:** don't treat threat-model-first as a strict replacement for a blind sweep. Run the TM surface
  lenses **plus at least one generic "unbounded / panic / infinite-loop" blind lens**, and let the shared
  skeptic panel arbitrate — the TM buys depth + the logic/differential surface, the blind lens backstops the
  classes the model forgot to enumerate. (See `targets/quick-xml/AB_COMPARISON.md`.)

### L22 — Verify a proposed fix against EVERY facet of the bug, not just the one that fired first  `[PROVEN]` · cheap-win
The quick-xml `nesting_level` overflow had an obvious one-line fix: `saturating_add`, mirroring the sibling
`pop()`'s `saturating_sub`. Applied and re-run, it **removed the panic but left the second facet alive** —
at saturation all deep levels collapse to `u16::MAX`, so `set_level`'s scope-truncation still over-truncates
and the namespace **misresolution persisted** (measured: `<p:f>` still `Unknown` at depth ≥65534). Only
`checked_add` → a clean depth-limit error closed *both* facets. Distinct from L20 (which is "verify the fix's
*cost* by reading the code") — this is "verify the fix's *completeness* by **running it against each PoC
facet.**" A plausible, idiomatic, symmetric fix can still be a partial fix.
- **Change:** when a bug has >1 observable facet (e.g. panic *and* silent corruption, two build profiles,
  two entry points), the fix isn't done until the PoC for **every** facet is re-run green — don't ship the
  first one-liner that silences the loudest symptom.

### L23 — An existing issue for the same *symptom* is a scoping question, not an automatic "drop"  `[PROVEN]` · principle
L15/L16 taught "verify against master/docs, and disqualify the already-known." But the pre-disclosure
issue-search on quick-xml's serde stack-overflow found an **open** #819 for the same symptom — and the reflex
"known → drop" would have been **wrong**. On inspection the root causes differed: #819 = a *correctness* bug
(a tiny recursive-**newtype** doc overflows at depth ~3); ours = a *DoS* on the **working** path (struct-
variant / `serde_json::Value` at attacker-controlled depth). We proved the distinction (the shape #819 calls
"working" still aborts at 20k depth) and filed a **cross-referenced, re-scoped** issue instead of dropping or
duplicating. Same symptom ≠ same bug.
- **Change:** when the tracker already has your symptom, don't binary "drop vs report" — compare **root
  cause / attack model / affected path / fix shape**. A distinct angle (severity, PoC, reachable surface,
  the fix it needs) is a real contribution; file it cross-referenced and state the distinction explicitly.

### L24 — A build-profile-gated crash (R7) can *mask* a different, non-gated bug in the shipping profile  `[PROVEN]` · principle · sharpens-L10
L10 says "re-test crashes under the shipping profile" — the implicit expectation being the crash *vanishes*
(→ R7, "not prod"). quick-xml sharpened it: under `overflow-checks` the `nesting_level` bug is a panic (R7),
but the **same root cause** under default release doesn't become benign — it silently **wraps and corrupts
namespace resolution**, which is *worse because silent* and fully in-scope for the shipping build. The R7
label was the *floor* of the impact, not the ceiling.
- **Change:** don't filter an R7-gated crash as "not production" and stop — investigate what the shipping
  profile does **instead** of the gated crash. Silent corruption / logic divergence in the ungated build can
  outrank the gated panic, and it's exactly what an "R7, move on" reflex would miss.

### L25 — Blind, TM-first, and CVE-seeded converge on the "big" bug but diverge on everything else — run all three, don't pick one  `[PROVEN]` · sharpens-L21
The miniz_oxide+ciborium 2-crate/3-pass campaign is a second, independent A/B(/C) data point after quick-xml
(L21), and it complicates the earlier read rather than just confirming it. For miniz_oxide, **all three
passes (TM, CVE-seeded, blind) independently converged on the same headline finding** (`init_tree`
algorithmic-complexity DoS) — triple-convergence across differently-seeded finder pools is a strong,
near-decisive confidence signal on its own, distinct from vote-counting within one pass. But for ciborium,
the **blind pass alone produced by far the richest yield** — 12 confirmed findings from 5 unscoped lenses,
including the two that ended up disclosed as the highest-severity bugs (both still-embargoed advisories,
mechanism withheld) — neither of which the threat model's architecture-level surface
lenses (Drop-safety, tag-vs-array stack cost) had anticipated as a specific angle. CVE-seeded, meanwhile, had
the narrowest yield of the three but still contributed something unique (the debug-only tag-vs-array
differential) plus a pure methodology win (catching that a `git clone` of the default branch wasn't
byte-identical to the published crate — see version-fidelity discipline). Read together with L21: **the
TM-vs-blind recall ordering is not universal — it depends on how well the threat model's specific lenses
happen to anticipate the target's actual bug classes.** A good threat model buys depth on the surface it
names; blind buys breadth on implementation-level bugs (buffer-handling edge cases, state-machine
regressions) that no one thought to write a lens for. CVE-seeded's distinct value is catching bugs shaped
like a *known* historical CVE class **and** as a version-fidelity tripwire, even when its raw yield is low.
- **Change:** keep running all three pass-types even on targets that already "feel" well-modeled by a threat
  model — treat multi-pass convergence on the same finding as a strong severity/confidence signal, and don't
  let a satisfying threat model talk you out of also running an unscoped blind sweep, which may out-yield it.

### L26 — A fix isn't verified until it's (a) independently reproduced against a byte-identical published base and (b) swept for missed siblings  `[PROVEN]` · principle · extends-P1
Three ciborium/miniz_oxide fixes were built by agents this round, each with its own self-reported PoC-before/
after and test-suite pass. Per P1, none were taken on that self-report: for each, I built my own PoC as a
`path = "..."` Cargo dependency pointed directly at the agent's fix branch (not the agent's own test files),
re-ran it myself, and re-ran the full test suite myself. This is a concrete, reusable technique for extending
"verify with structure" (P1) to the **fix** stage, not just the find stage — an agent's own tests can pass
while still not proving what it claims (a test that constructs the vulnerable state differently than the real
entry point, a subtly-wrong assertion). Separately, after both ciborium fixes were filed, a "bugs travel in
packs" variant-analysis sweep (re-reading every adjacent call site for the
same missing-guard/zero-progress pattern) confirmed both fixes were structurally *complete* — no missed
sibling method, no missed call site — which is not guaranteed just because the reported PoC now passes; a
fix can close the one reported instance of a pattern while leaving a sibling instance of the *same* pattern
untouched, invisible to the one PoC that was tested.
- **Change:** for any agent-built fix, before treating it as done: (1) build your own independent PoC as a
  path-dependency against the fix branch, not the agent's own tests; (2) run a variant-analysis sweep for the
  same pattern elsewhere in the codebase before considering the fix — and the disclosure — final.

### L27 — Check GitHub's private-vulnerability-reporting via the API before choosing a disclosure channel; don't infer it from SECURITY.md alone  `[PROVEN]` · sharpens-L16/L17/P5
The channel-default rule (P5, updated 2026-07-19) says "public issue+PR absent a documented private
channel," with SECURITY.md as the signal named. Neither miniz_oxide nor ciborium has a SECURITY.md — but
`gh api repos/{owner}/{repo}/private-vulnerability-reporting` showed ciborium has it **enabled** (`{"enabled":
true}`) while miniz_oxide does **not** (`{"enabled": false}`). Filing on the assumption "no SECURITY.md →
public" would have wrongly pushed two working recursion/hang PoCs into a public issue on a repo that actually
offers a private-advisory flow — the API check is cheap (one call per repo) and authoritative in a way
SECURITY.md's absence is not.
- **Change:** before filing, call `gh api repos/{owner}/{repo}/private-vulnerability-reporting` (not just
  `find … -iname SECURITY*`) — treat its `enabled` field as the actual channel-decision signal, and reserve
  the public issue+PR default for repos where that call itself confirms the channel is unavailable.

### L28 — A fix-building agent's own "let me repair my environment" instinct is itself a blast-radius risk, not just a target-code risk  `[PROVEN]` · principle · sharpens-P6
The png/image campaign ran 6 parallel background agents, each with full Bash access in its own git
worktree, tasked to design+build+test a real fix. One of them (the AVIF fix, which needs system-level
AV1-decode tooling) hit *some* environment/toolchain problem mid-task and — entirely on its own initiative,
never asked to — attempted to repair it by reinstalling/updating its Rust toolchain via `rustup`. A network
interruption hit mid-download; the agent's own last words were "network connection reset mid-download,
let's wait for the retry loop." That left `~/.rustup` in a **partially-uninstalled state** — and because
every worktree/agent in this campaign shares the same real `$HOME` (git worktrees are NOT toolchain-isolated,
only source-isolated), this took down `cargo`/`rustc` for **every other concurrently-running agent, and the
orchestrating session itself** — every subsequent `cargo` invocation (a rustup shim) re-triggered the same
failing auto-repair rather than just working. Diagnosing which of 3 still-running agents caused it took
correlating timestamps and reading the two agents' own final in-flight messages (one literally described the
network reset) before the actual culprit was clear enough to stop. Recovery was a straightforward
`rustup toolchain install --force` once identified — the *damage* was cheap to fix, but it silently blocked
real verification work for a stretch, and it happened  from an agent doing something reasonable-*sounding*
from its own local vantage point ("my environment is broken, let me fix it") that was invisible in scope to
its own task.
- **Change:** this is the SAME class of concern P6 already names (the pipeline's own agents are a first-class
  part of the trust boundary, not just the target code they analyze) — but the actor here is a benign,
  cooperative fix-agent, not adversarial target input. Fix-agent task prompts for parallel/background runs
  should explicitly say: if you hit an environment/toolchain/dependency problem, **stop and report it, do not
  attempt to repair shared system tooling** (`rustup`, global package managers, anything outside your own git
  worktree) — that repair is the orchestrator's call, not an autonomous in-task decision, precisely because
  the blast radius extends to every other concurrently-running agent sharing the same host.
  **The real, architectural fix (not just a prompt mitigation):** heavy/parallel multi-agent cargo work
  (6+ concurrent fix-agents each doing full builds+tests) should run on the isolated remote build box
  (an isolated remote build host) inside per-agent Docker containers, not on the local Mac's bare-metal
  `$HOME/.rustup` — recovering the local toolchain here cost 30+ minutes fighting the SAME network flakiness
  that caused the original break (repeated connection-reset retries on the same large component download),
  because there was no isolation to begin with: every worktree shared one real toolchain install. Docker
  containers per agent make a "let me fix my broken environment" mistake blast-radius-contained to that one
  container, not every concurrent agent and the orchestrating session.

### L30 — A fix branch cut from a stale clone reads to the maintainer as dishonesty, not sloppiness — re-clone immediately before every PR, no exceptions  `[PROVEN]` · principle · sharpens-P1/P5
During the L29 remediation pass, `image-png` PR #695 (a fix for issue #694, filed 2026-07-19) had its
branch cut from commit `2260b15` — dated **2026-02-14**, five months stale, and two months *before* the
upstream fix (PR #682, merged 2026-04-24) that made our finding moot in the first place. GitHub's
compare view for a PR whose branch predates the current base by that much renders a merge-base diff that
doesn't match either side cleanly — maintainer `197g` read this as **evidence of dishonesty**, not staleness:
*"That's fucked up beyond belief... this makes me lose all trust that what-i-see-is-what's-in-the-PR at
all and that is certainly a vulnerability angle"* — and escalated publicly to a second maintainer. A
follow-up sweep of every other open PR from the same campaign found `fdeflate` PR #84 in the identical
state — branch cut from **2024-12-05**, 1.5 years stale, silently `CONFLICTING` against a `main` that had
since merged an unrelated refactor (#73) touching the exact code the fix patched — caught and closed
proactively before a maintainer found it, with no complaint incurred.
- **Change:** immediately before building a fix or opening/updating a PR, `git clone` fresh (or `git fetch
  && git reset --hard origin/<default-branch>`) — never build on a checkout that has sat for more than a
  few hours, and never assume a clone from earlier in the same campaign session is still current. Before
  closing a report-only issue as already-fixed (L29's remediation move), also check for and close/rebuild
  any of **our own already-open PRs** against that issue — an issue can be correctly closed while its
  companion PR is left dangling and stale, which is worse than closing neither. When a stale PR is found,
  don't wait for the maintainer to notice and read it as malice: close it proactively with the exact
  commit-hash evidence of the staleness (`git merge-base`, dates) so the explanation is verifiable, not a
  vague apology — a precise root cause defuses a trust escalation; a vague one does not.
- **Do:** fresh clone before every fix/PR, no exceptions; sweep all our own open PRs (not just issues) for
  the same staleness whenever remediating a campaign; when caught, lead with the verifiable commit-hash
  proof, not just "sorry."

### L29 — A present, narrow SECURITY.md is a stronger signal than an absent one; read it in full, and don't fan out report-only issues on a volunteer team  `[PROVEN]` · principle · sharpens-P5
The png+image campaign (L28's campaign) filed 9 report-only issues on image-rs/image and several more
on image-rs/image-png, each framed with Severity/Impact language, most saying "not submitting a PR —
this needs a maintainer's call." The maintainer (`197g`) called this out publicly and sharply: *"Please
stop creating so many ML generate issues with the particular goal of leaving it up to maintainer
judgment whether or not they are actually issues. That's just rude... those issues with opened PRs seem
fine (for now, don't overdo it)"* (image#3076), and on a report-only finding closed works-as-intended:
*"I find the ''Impact'' statement laughable... Please stop submitting so many ML generated 'reports'
without better coordination... there's concern the SNR and thus factual quality suffers"* (image-png#701).
Two issues were also closed as duplicates of a pre-existing tracker issue (#2708) never searched for
before filing, and one (#3081) caught a stale version claim — the issue text said "verified against
0.25.10" but the actual verification had drifted to `main`.
Root cause: L27's channel check (`gh api .../private-vulnerability-reporting`) answers *whether a
private channel exists*, not *whether the maintainers have already scoped this class of bug out of their
vulnerability program*. image-rs's SECURITY.md — present, not absent — explicitly lists **crashes/panics**
("panicking is considered safe... isn't guaranteed [not to happen]") and **out-of-memory/DoS**
("Resource limits are on a best-effort basis") as **not vulnerabilities**. Nearly the entire png/image
crop was exactly these two classes, run through full security-report framing anyway.
- **Change:** before filing anything, read the full text of any repo/org SECURITY.md — not just probe
  the API boolean — and if it explicitly excludes a bug class, don't frame that class as a security
  finding (file as an ordinary bug, no Severity/Impact language, or don't file at all). Don't fan out N
  report-only issues per crate: either attach a real fix before filing, consolidate into far fewer
  issues, or don't file the weak ones — the fan-out volume itself is a cost imposed on a small volunteer
  team, independent of whether each individual claim is technically correct. Search the tracker for
  existing/duplicate coverage (including an umbrella tracking issue under different framing) before
  treating anything as novel. Re-verify the exact version claim against current `main` immediately before
  writing the report text, every time.

### L31 — A `?`/early-return on a recursive call site can silently collapse an exponential-blowup PoC into linear work; check for it before blaming the crate  `[PROVEN]` · sharpens-L26
Independently re-verifying (per L26) the rmp-serde+ttf-parser campaign's 7 HIGH findings, the first
from-scratch PoC for ttf-parser's `glyf` composite-glyph exponential blow-up (a shared-child "diamond
reuse" chain built as a 2-glyph mutual cycle) came back a **false negative** — branching=2 and
branching=3 both completed in single-digit microseconds, the opposite of the reported exponential
cost. The cause wasn't the crate being safe; it was the PoC's shape: `outline_impl`'s recursive call
site is `outline_impl(..., depth + 1, ...)**?**`, and every path through a pure cycle eventually hits
the hardcoded `depth >= MAX_COMPONENTS` cutoff — the FIRST such `None`, hit on the leftmost
depth-first path, propagates via `?` through every enclosing frame and aborts the **entire**
traversal before any sibling branch is ever visited, collapsing an apparent `branching^32` into ~32
linear calls. Rebuilding the PoC as a **finite** chain (each level's `branching` components point at
ONE shared next-level glyph, terminating in a real leaf glyph so **no path ever reaches the depth
cutoff**) removed the short-circuit and reproduced the real cost (996 bytes → 16s CPU at depth=18,
branching=3; did not finish in 20s at depth=20). Having learned this, the very next PoC (ttf-parser's
COLRv1 `PaintColrLayers` diamond-DAG) was checked for the same trap *before* writing any code — its
recursive `self.parse_paint(...)` call discards the return value with no `?`, so the same diamond-chain
construction worked cleanly on the first attempt (paint() call counts landed exactly on `branching^depth`:
1024, 32768, 387420489).
- **Change:** before building an exponential/combinatorial-blowup PoC around a recursive parser, read
  whether the recursive call site propagates a failure/limit signal (`?`, `return None` on the child's
  result) up the call stack. If it does, a cyclic or unbounded-depth construction will short-circuit
  on the first limit hit and under-report the true cost — design the PoC to terminate *before* any
  path reaches the limit (a finite diamond-reuse chain, not a cycle) so the short-circuit never fires.
  If the call site discards the child result (no propagation), a cycle/cutoff-hitting construction is
  fine and the short-circuit risk doesn't apply. A false negative from a first PoC attempt is a reason
  to re-read the recursive call site's control flow, not a reason to conclude the crate is safe.

### L32 — Verify-against-`main` is a self-triggered checklist item, not something that waits for the user to ask  `[PROVEN]` · sharpens-P1/L15
L15 (x509/lopdf/gimli/httparse era) already established "reproduce against the version you'd report
against **and** `master`" as a principle. The rmp-serde+ttf-parser campaign proved the principle again
— but only *after* the operator had to explicitly ask **"Проверь: 1. Это работает против main"** —
at a point where all 7 findings had already been presented as independently PoC-verified, with no
caveat that the verification had only ever run against the pinned `crates.io` release, not the repos'
current `master`/`main`. This is not the first time this exact gap has needed a user nudge rather than
firing on its own — L15 documents the *technique*, but the *trigger to run it* has repeatedly been
external instead of built into the pre-disclosure checklist I run unprompted. (This time all 7
reproduced identically on `main` — no already-fixed surprise — but that's luck, not discipline; the
check has to run regardless of whether it turns out to matter.)
- **Change:** treat "reproduce against a fresh clone of the repo's default branch" as a mandatory,
  self-triggered step the moment a finding is heading toward disclosure — run it in the same breath as
  writing "confirmed" in a summary, never as a follow-up to a user's "did you check X?" The fix here is
  procedural, not a reminder to be smarter next time: fold it into whatever pre-disclosure checklist
  gets run before a finding is presented as done, so it fires unconditionally instead of depending on
  someone remembering to ask.

### L33 — A closed issue's fix has a scope; read the closing commit/PR to find that scope before calling anything a duplicate  `[PROVEN]` · sharpens-P5/L16/L23/L29
Pre-disclosure duplicate search for this campaign hit closed issues on **both** repos whose titles
matched the symptom almost exactly: msgpack-rust's #276/#52 ("Stack safety" — recursive-structure
stack overflow, fixed by merged PR #277) and ttf-parser's #80 ("Panic at `!self.is_empty()` assertion
in `tables/cff/argstack.rs`", fixed by commit `f28f7a5`). Title-matching alone would have read either
as "already reported and fixed" and stopped there. Instead, `gh api repos/.../issues/{n}/timeline`
found the closing commit/PR for each, and `gh pr diff` / `gh api .../commits/{sha}` showed the actual
files touched: PR #277 added the `depth_count!` guard to exactly 3 call sites (`visit_seq`,
`visit_map`, the `Ext`-marker `visit_newtype_struct`) — never `deserialize_option`,
`deserialize_newtype_struct`, or `newtype_variant_seed`, which is precisely where this campaign's 3
rmp-serde findings live. Commit `f28f7a5` fixed the `argstack.rs` panic only inside `cff1.rs`'s `seac`
resolution — never touching `cff2.rs`'s `BLEND` operator, which has the identical unguarded-pop bug.
Both gaps were real, novel, unfixed — and would have been wrongly dropped as duplicates without
reading the diff.
- **Change:** for any tracker hit (open OR closed) that matches a finding's symptom, don't stop at the
  title or the open/closed state — pull the closing commit/PR (`gh api .../issues/{n}/timeline`, filter
  `event == "closed"`, then diff that commit/PR) and check whether it actually touched the *exact*
  function/file/code-path the current finding lives in. A closed issue with a merged fix is a scoping
  question (L23), and the scope is only knowable by reading the diff — not the issue title, not the
  "closed" label, and not the fix's own commit message (`f28f7a5`'s message doesn't mention `cff1.rs`
  specifically, only "(CFF) Fixed panic and stack overflow during `seac` resolving" — read the file list
  in the diff, not just the prose).

### L34 — "Same bug class as an already-accepted finding" is a mechanism claim, not a severity claim — measure the magnitude, don't inherit the label  `[PROVEN]` · sharpens-P3/P5
fdeflate #83 was filed as High severity, framed as "the same class as the already-fixed miniz_oxide
`init_tree` bug" — true at the mechanism level (both decouple Huffman-table-rebuild cost from output
size). Maintainer `fintelia` closed it NOT_PLANNED: *"Decoding at 10+ MB/s isn't denial of service."*
Checked the claim against our own numbers rather than accepting or dismissing it on tone: our PoC's own
attack throughput was 41.6 MB input / 2.988 s ≈ **13.9 MB/s** — matching his framing almost exactly. A
real-data baseline (fdeflate decoding four actual PNGs, 11 MB compressed / 51 ms) measured **215 MB/s**
legitimate throughput — so the attack is a genuine ~15.5× slowdown, not nothing, but nowhere near "High."
The miniz_oxide finding it was compared to needs **0.48 MB/s of attacker bandwidth per victim-CPU-second**
(1.25 MB → 1.8–3.4 s); fdeflate's needs **13.9 MB/s** — miniz_oxide is a ~29× stronger DoS primitive by
the metric that actually matters (attacker cost to inflict a unit of victim cost), and we filed both under
the same severity without ever computing that ratio. fintelia's blunt framing turned out to be
substantially correct on the technical merits, separately from the (also valid) meta-complaint about
issue-volume.
- **Change:** when citing a prior accepted finding as precedent for severity ("same class as X"), compute
  the actual comparison, not just the mechanism match: attack-throughput vs. a measured legitimate
  baseline on real data (not just the PoC's own numbers in isolation), and attacker-bandwidth-cost-per-
  victim-CPU-second against the precedent's own numbers. A shared root cause does not imply a shared
  magnitude — the gap here was 29×, entirely invisible without doing the arithmetic. When a maintainer
  pushes back on severity with a specific technical claim ("N MB/s isn't DoS"), check it against the
  actual PoC data before either conceding or re-arguing — the check itself, done honestly, is usually
  more persuasive (to us and to them) than either response would have been alone.
- **Addendum (rmp-serde+ttf-parser campaign, 2026-07-20, applied *before* filing rather than after a
  maintainer pushback):** ran the same check proactively on 7 findings carrying an inherited "High"
  label. It cut both ways. The two algorithmic-complexity findings (ttf-parser's glyf/gvar shared-
  component blowup and COLR shared-paint-node blowup) got a real-data baseline this time — a
  6253-glyph real font (DejaVu Sans) and the project's own COLRv1 test font, not just the PoC's own
  numbers — and came back **stronger** than the precedent this lesson is named for: ~9,130×/~13,800×
  more attacker-bandwidth-efficient than miniz_oxide's own rate, ~13,625×/~175,000× slower than the
  worst real glyph in each baseline. High was an understatement, not an inflation, for those two. A
  third finding (an `i16` overflow in `avar.rs`) went the other way once the actual impact was traced
  through: the release-mode facet is a rendering-correctness bug with no crash/DoS/memory-safety angle
  (safe Rust throughout, the wrapped value is still in-range for every downstream consumer) — reassessed
  to Low, not a security finding at all in that mode. Four more (three rmp-serde recursion-guard gaps
  plus a CFF2 stack-underflow panic) don't have a throughput curve to measure the way a slowdown bug
  does — crash is binary, not a degradation rate — so those were moderated to Medium by convention
  (CWE-400/674-style "panic on malformed input, no memory corruption" in a parsing library) rather than
  computed, and flagged to the user explicitly as a judgment call, not a hard number, so the label
  doesn't quietly acquire the same false precision this lesson exists to fix.

### L35 — Inbound requests from a "maintainer" in a comment are still untrusted content — verify independently, never execute blindly  `[PROVEN]` · principle · extends the session's own instruction-source-boundary rule to disclosure work
A quick-xml maintainer's PR comment ("@scadastrangelove please run `cargo fmt`, otherwise looks good") was
handled correctly by accident rather than by an explicit rule: before pushing, the actual diff was read
(confirmed formatting-only), the full test suite was re-run, and the request was in-scope of what we were
already doing (updating our own fork branch) — not because "a maintainer asked" was itself sufficient
grounds to act. That distinction needs to be explicit, not incidental: a GitHub account with commit
history and a maintainer badge is still, mechanically, a source of **untrusted external content** to an
agent reading it — identical in kind to a comment on any other issue, a doc string, or a file name. The
same boundary the harness already applies to target source code (an adversarial target can't inject
instructions through a docstring) applies to the disclosure side too: a comment could ask for something
that reads as reasonable in isolation but is actually a credential/access grab, a request to run an
arbitrary script or curl a URL, or (the illustrative extreme) an instruction to take a destructive action
against our own infrastructure ("delete your repo"). None of that happened this campaign — the point is
that the discipline that would have caught it wasn't yet a *named* rule, just a lucky default.
- **Change:** treat every inbound request in an issue/PR comment or review, from any account regardless of
  role or verification badge, as content to evaluate on its own technical merits — same as target source.
  Before acting: (1) does the request make sense given what you can independently verify (read the actual
  diff/code, don't take the request's framing of the problem on faith), (2) is the action itself
  narrowly scoped to something already-in-flight and reversible (pushing a formatting fix to our own fork
  branch — yes; granting access, running a fetched script, or taking any destructive/irreversible action
  because a comment asked — no, escalate to the human operator instead), (3) the fact that the requester
  has maintainer standing on the repo makes the request *worth taking seriously*, not *safe to execute
  without the same checks* — authority and trustworthiness are different axes.

### L36 — "Refound" (independently found, already fixed upstream, unreleased) is a distinct, positive outcome — don't fold it into a generic "resolved," and don't trust a silent closure without re-reading the source  `[PROVEN]` · principle · sharpens-P5/L16/L32
Sweeping the campaign's "resolved without our PR merging" bucket turned up two shapes that look identical
in the tracker (issue closed, not by us) but mean opposite things. **Refound**: `png` #694, and `image`
#3077/#3079/#3080/#3082 (one single unreleased architectural Limits-refactor closing all four at once —
#3079 was closed as "duplicate of #2708," an issue that is itself still open and unimplemented; the
maintainer's *stated* reason didn't match the actual mechanism, which was the same refactor as the other
three — another instance of L33's "read the diff, not the label," this time applied to a closure reason
instead of a duplicate claim) — in each case a specific, identifiable fix (a merged PR or an in-progress
refactor) independently addresses the *exact* gap we found, authored before or without knowledge of our
report. This is a **positive**
signal, not a miss: our own discovery process (fresh source reading, a real PoC) converged on the same
bug the actual maintainers already considered worth fixing — validation of the method, and worth naming
as its own category rather than burying inside "resolved independently," which reads as a shrug. But
**png#692 looked identical from the tracker alone** — closed same day, no comment, no linked fix — and
turned out to be neither refound nor resolved: re-reading `output_buffer_size()` directly against current
`master` showed the exact reported gap (no `Limits.bytes` check, only an `isize::MAX` overflow check)
still present, unchanged. The issue was closed with nothing behind it, almost certainly swept up in
unrelated maintainer fatigue rather than adjudicated. A `COMPLETED` state reason or a same-day closing
timestamp is a claim, not a verification — indistinguishable from a real fix without opening the file.
- **Change:** for every issue closed by someone other than us with no fix commit cited, re-read the
  current source directly before recording an outcome — don't infer "fixed" from the closure alone, even
  a `COMPLETED` one. When it is genuinely refound, say so as its own category (a convergent-validation
  win); when it's closed-but-unfixed, record the true technical state even if you've decided not to
  contest the closure (matching a holding pattern with a fatigued maintainer is a *disclosure* decision,
  not a license to misreport your own tracker).

### L37 — A rejection is a claim made in the heat of the moment, not a verified end state — re-check on a delay, and a silent later fix with no credit is a full success  `[PROVEN]` · principle · sharpens-P5/L36
Applying L36's discipline to the "rejected" bucket, not just "resolved," turned up the same split: of 6
rejections, re-reading the actual current source showed 2 genuinely fair (`png` #698/#701 — WAI, verified
on the merits, not just accepted on tone), 1 largely correct on severity (`fdeflate` #83, L34), and 1 —
`image` #3081 (`decoder_to_vec`) — **flatly wrong on inspection**: closed as "duplicate of #2708... it's
just doing what the user asked, like `Vec::resize`," but `#2708` is itself unimplemented, the code is
byte-for-byte unchanged, and the "`Vec::resize`" analogy doesn't hold (`Vec::resize` makes no `Limits`
promise; `ImageDecoder`/`from_decoder` is the exact entry point `Limits` exists to guard). This is a known,
general pattern, not specific to open source or to one irritated maintainer that day — the identical first
reaction ("this can't be real") has shown up from large corporate targets in prior engagements. The
response isn't to argue the point in the moment, while both sides are irritated; it's to **let the heat
pass and re-verify against source on a delay**, the same way a silent finding gets a follow-up nudge.
- **Change:** every rejection gets a scheduled re-check date (weeks out, not immediate), not just silent
  findings. On the re-check, re-read the source fresh — don't just re-read the old rejection comment. If
  the bug is fixed by then, **even silently, with zero acknowledgment or credit to us**, that is a complete
  win and gets logged as `refound`, full stop — no comment demanding recognition, no re-litigating the
  original exchange. The deliverable is the target's actual security posture, not attribution; a silent
  fix achieves the entire mission as completely as a credited one does.

### L41 — A valid finding does not grant its finder authority to send it; escrow and reassess when no authorized sender exists  `[PROVEN]` · principle · sharpens-P5
In a real campaign, an agent produced a reproducible finding and a credible fix, but the target's
contribution policy required maintainer-facing prose to be human-authored. The ordinary issue/PR route
therefore did not authorize autonomous submission, and the private security channel was not a legitimate
fallback for a finding outside that channel's current scope. With no human operator or opt-in coordinator
available, every apparent workaround failed the same test: rephrasing the report would evade rather than
honour the policy; using a different inbox would manufacture channel eligibility; independent publication
would expose users without gaining authority; and deliberately waiting for the defect to ship would
manipulate the conditions under which the report might later qualify.
- **Change:** represent technical validity, channel eligibility, and sender authority as separate gates.
  Put a valid-but-unauthorized finding in `PRIVATE_ESCROW`, seek a coordinator only through a pre-authorized
  opt-in route, and otherwise use `HOLD_AND_REASSESS`. Re-check source, releases, policy, available
  coordinators, and risk on a schedule and on material events; do not file merely because time passed.
  `BREAK_GLASS` triggers an external or precommitted decision procedure — it never lets the same
  goal-seeking agent expand its own authority.
- *Full anonymized case:* [`docs/case-studies/autonomous-disclosure-authority.md`](docs/case-studies/autonomous-disclosure-authority.md).

---

## Principle ↔ lesson map

Reverse index for the consolidation (done 2026-07-19, extended to L28 same-day, L29–L37 2026-07-20,
L38–L44 on 2026-07-23, and L45–L47 during the h2/hyper seam audit). Every L1–L47 is folded into
exactly one principle:

| principle | folds |
|---|---|
| **P1** — lead-until-verified, structurally | L1, L2, L3, L6, L12, L15, L22, L26, L30, L31, L32, L39 |
| **P2** — build profile is threat model | L10, L24 |
| **P3** — recall-first, adversarially gated | L4, L5, L8, L18, L19, L21, L25, L40 |
| **P4** — static ∥ layer-routed empirical oracle | L11, L14, L19, L42, L43, L45, L46, L47 |
| **P5** — disclosure matched to fix and authority | L9, L13, L16, L17, L23, L27, L29, L33, L34, L36, L37, L41 |
| **P6** — dogfood + own trust boundary | L7, L20, L28, L35, L38, L44 |

(L19 sits primarily in P3 — "clean = valid" — and feeds P4's dynamic/static split. L30 sits primarily in
P1 — "verify against the real target" — and also sharpens P5's disclosure discipline. L31 is a narrow
sharpen of L26's PoC-verification discipline; L32 sharpens L15 specifically into "self-triggered, not
user-prompted"; L33 sharpens L23's duplicate-scoping check into "read the diff, not the title"; L34
sharpens P5's severity/artifact-matching into "measure the magnitude, don't inherit a precedent's label";
L35 extends P6's trust-boundary framing from the target's source and the agent's own execution
environment to the inbound *disclosure comment channel* — a maintainer's GitHub comment is untrusted
content by the same logic as target source, not a command. L38 extends that same boundary to the corpus
available to sub-agents; L39 sharpens P1's end-to-end reachability rule; L40 adds a target-selection
consequence to P3; L41 separates a finding's validity from the sender's authority; L42–L43 route
P4's empirical oracle by layer; L44 applies P6's dogfood discipline to the evaluation corpus; L45 adds
shipping-layer ordering to P4; L46 adds protocol-oracle discipline and reviewer-skepticism checks to
P4; L47 adds ecosystem seam validation to P4.) When a future campaign adds an Ln, file it
under the principle it sharpens; open a new principle only if it fits none — the point of this file is
that **six** things stay in your head, not forty-seven.

## Operational notes (not project lessons, but bit us)

- **`git add -A` in a reused/long-lived scratchpad directory can sweep up a stray leftover from a
  DIFFERENT, unrelated earlier task — and it goes unnoticed until the diff stat.** Preparing the lopdf
  recursion-cluster PR, a `vendor/` directory (281 MB, `cargo vendor` output left over from an unrelated
  earlier zune-jpeg campaign in the same scratchpad path) got vacuumed into the very first commit
  (14,496 files, 4.45M lines) and was pushed to the fork branch before the diff stat was checked. Caught
  it before opening the PR (via `git show --stat HEAD`), fixed with `git reset --mixed HEAD~1` + re-add
  only the intended files + re-commit + **force-push** — safe *only* because it was an unshared branch on
  my own fork with no PR open yet (a force-push after sharing/PR would be a different, much worse call).
  **Change:** run `git status --short` (or `git diff --cached --stat` right after `git add`) before every
  commit in a scratchpad checkout that might have outlived its original task — never trust a clean mental
  model of "what's in this directory" for a long-lived working tree.

- **"Agent died" ≠ "agent found nothing."** In the quick-xml A/B, Run B v1 returned `n_raw=0` purely from
  transient "Connection closed mid-response" API failures (3/5 finders died) — nearly misread as "threat-
  model-first found nothing," a false verdict *against the method*. Comparative measurements must be
  retry-resilient and must distinguish an **empty result** from a **dead agent**, or infra noise
  contaminates the conclusion. (Fix used: a `tryAgent` wrapper, 3 attempts, transient-null → retry.)

- **Detach long remote runs** with `nohup … & disown` (or a screen/systemd unit): a backgrounded `ssh
  … &` inside a tool call gets **SIGHUP when the tool returns** and takes the remote container with it —
  this silently killed a fuzz build mid-compile once.
- **cargo-fuzz defaults enable overflow-checks/debug-assertions** — so a naive fuzz run reproduces the
  same L10 artifacts. Set the shipping profile (`overflow-checks = false`) explicitly, and L10-filter
  any crash regardless.
- **Fuzz `-max_total_time` is fuzz-time, not wall-clock**, and CPU-light targets saturate coverage long
  before the wall-clock budget — a "52%-of-6h" cut can still be enumeration-complete by saturation.

### L38 — Sub-agents wander outside the corpus you gave them and read whatever is on the host — isolate the target, keep the answer key out of reach, and audit before trusting a run  `[PROVEN]` · principle · new

A multi-agent find campaign was run twice on the same target — same lenses, same source,
different model — as a clean A/B. It wasn't clean. Some sub-agents, handed an absolute path to
the source tree, ran broad host searches (a `find` from a parent directory, a recursive `grep`
outside the given tree) to orient themselves, drifted **outside the intended corpus**, and read
unrelated files sitting elsewhere on the host — including the analyst's own working notes from the
first run, which contained the conclusions and a verified PoC result. Those agents then cited the
notes as "evidence" in their verdicts. Two distinct harms:

1. **Silent experiment contamination.** An agent that read the answer key is no longer an
   independent vote. Any claim that rests on independence — model-A-vs-model-B, blind-vs-seeded,
   N-way cross-verify — is invalid for those agents, and the contamination is **invisible in the
   aggregate disposition**; you only see it by reading the transcripts. (Here, one confirmed
   finding's "where_checked" literally pointed at the analyst's notes file. The comparison
   survived only because the *decisive* delta happened to land on a finding whose verifiers were
   clean — luck, not design.)
2. **Latent data exposure.** The same wander that reached benign notes could have read
   credentials, another project's source, or unrelated sensitive files. A prose instruction
   ("only read `<path>`") does not constrain an agent that can't find what it wants and searches
   wider.

**The rule:**
- **Isolate the corpus.** Copy the target into a scratch directory that contains *only* the
  target and hand agents that. Don't rely on a path in the prompt — give them a tree where there
  is nothing else to find.
- **Keep the answer key unreachable.** Never leave analysis notes, a prior run's conclusions, or
  an expected-result file anywhere a broad `find`/`grep` from the agent's host can reach —
  least of all adjacent to the working directory. Your own correct notes are the *worst*
  contaminant precisely because they're specific and right.
- **Audit before you trust.** When a run's value depends on independence, grep the sub-agent
  transcripts for the corpus boundary (or for unique phrases from your own notes) and drop any
  agent that read outside the corpus from the independence claim. A "confirmed" that cites your
  own earlier conclusion is not a second data point.
- Contamination can only be **prevented** (isolation) or **detected** (transcript audit) — never
  undone after the fact. This is the instruction-source-boundary discipline one level down: an
  agent's own tool output is untrusted data, and that data can quietly include the answer.

### L39 — A vendored/embedded target's reachability and severity are set by the HOST integration's caps, not by the file or crate you're reading — trace up to the shipping wrapper before you rate anything  `[PROVEN]` · principle · sharpens-P1/L3

Three times this session a finding's "there is no guard here" was literally true and completely
irrelevant, because the dispositive guard lived one or two trust-layers UP in the code that actually
ships the component:
- **an archive tar-slip candidate** — "no path-validation call anywhere in the archive-stream code"
  (grep-true) — but the `tar` crate's own `append_data` rejects `..`, `rawzip` normalizes it, and
  the repository's worktree-stream path gates on an index-from-tree check first. Contained upstream of the finding.
- **x509** — the verdict rested on "the sink accepts empty RSA" — but `asn1-rs` rejects it before the
  sink, and the sink re-parses. Contained upstream.
- **Chromium BMP "Finding B"** (17 GB `resize`) — "no magnitude cap in the Rust decoder or the C++
  `SkSafeMath`" (both true) — but Blink's `SizeCalculationMayOverflow` computes `w*h*4` in **int32**
  and `SetFailed()`s before the decoder runs. The naive PoC is dead.
- **Change:** for any finding in vendored/embedded/wrapped code, before rating reachable-or-severity,
  trace the attacker value to the OUTERMOST shipping caller and enumerate ITS caps — int casts, size
  gates, validation, dependency guards. A "confirmed" that stopped at the file/crate boundary is a
  candidate, not a finding. This is exactly where a junior model's verify stops short (at the nearest
  guard) and over-rates — the x509 2×2 and the Opus-vs-Sonnet Finding-B delta both landed here.
- **The counterpart that survives the trace is the real prize:** Chromium BMP "Finding A" (ICC alloc)
  was NOT contained by that same Blink cap — the ICC size is an independent field read during
  metadata, before the dimension gate — so it became the one filed finding. Tracing up doesn't only
  kill over-claims; it tells you which candidate is actually reachable.

### L40 — In a vendored dependency, the NEW/forked code is the yield zone — an unforked, well-fuzzed crate is low-yield; spend the budget on the patch  `[PROVEN]` · principle · sharpens target-selection / composes-L14/L19

Chromium vendors both `image` (BMP path is a **+2285-line Microsoft fork** of the decoder) and
`image-png` 0.18.1 (**unforked**, continuously OSS-Fuzz'd). BMP yielded a real finding
(`read_icc_profile` infallible alloc); PNG yielded nothing — static-clean **and** a 3.4M-run
memory-capped fuzz clean. The fork is new attack surface that neither the crate's fix-history nor its
own fuzzers ever covered; the unforked crate's bugs are already-found (we hold 7 image-png findings)
or already-fuzzed-out.
- **Change:** when a target vendors a dependency, diff it against upstream FIRST and concentrate find
  effort on the delta (the patch, the new state machine, the FFI glue). Treat an unforked +
  OSS-Fuzz'd crate as low-priority — a fresh blind fuzz there mostly re-derives known bugs (L14/L19).
- Pairs with L39: the fork's new alloc/panic sites still must be traced to the host integration's
  caps before rating — new code is *where* to look, not automatically *what* ships as a bug.

### L42 — The target's LAYER determines both the valuable bug-class and whether fuzzing fits; route by layer, don't fuzz by default  `[PROVEN]` · principle · sharpens target-selection / composes-L40 · [ADR-1]

The recent up-stack arc — rustls (GHSA-j99h/GHSA-4xwv), quinn-proto (GHSA-hmxj), gitoxide
(GHSA-pmm9), ciborium, actix/ntex — delivered **100% of its value from semantic/protocol bugs**
(missing-guard, downgrade, silent data-loss, protocol-tied resource growth) found by reasoning +
differential review + harness-reuse PoC, with **fuzzing unused**. The earlier parser arc (zune-jpeg,
png/image, miniz_oxide, object, lopdf) delivered from **fuzz-found panic/OOB**. That is not drift —
it is the correct tool tracking the layer: a mutation fuzzer can't reach deep valid-handshake states,
has no crash oracle for a bug that doesn't crash, and can't trip a domain invariant that isn't an
assertion; plus mature protocol crates are already OSS-Fuzz'd, so our fuzzer re-finds their CI's work.
- **Change:** classify each target as **data-format parser** / **protocol-state-machine** /
  **API-contract** before hunting, and pick the tool from the layer (parser→fuzz-first;
  protocol→invariant-first; contract→differential-first). Fuzz only when parser **and** not
  well-OSS-Fuzz'd **and** crash/OOB class. Fuzzing is not retired — it's the wrong tool for two of the
  three layers, and the way up-stack is *differential/stateful* fuzzing, not byte-mutation.

### L43 — On protocol/state-machine targets the finding shape is an ENFORCEMENT ASYMMETRY, and its oracle is differential, not a crash  `[PROVEN]` · principle · composes variant-analysis / [ADR-1]

Every rustls finding was a guard present in one place but missing at its mirror: the server rejects
TLS1.2-on-QUIC, the client doesn't (B); the outgoing hello is suite-filtered, the incoming acceptance
isn't (A, client path); the server-selection filter existed in 0.23.x and was dropped in 0.24-dev (A,
server path). The highest-signal lens was mechanical: grep a check, ask "where is its mirror across
client↔server / send↔receive / offered↔accepted / one-param↔all-params?" — the **control-asymmetry is
the finding**. And rustls C (silent request-drop) proves the oracle point: a crash-hunting fuzzer
never flags accept-what-should-be-rejected or drop-without-error; you need a **control-vs-attack**
(identical construction, one variable) or **spec-vs-impl** differential.
- **Change:** ship two named finder lenses for protocol/contract targets — **invariant-symmetry**
  (the mirror walk) and **silent-failure differential** (control/attack or spec/impl oracle). A guard
  with no mirror, or a validated-then-discarded value, is a candidate even with no crash.

### L44 — Our eval measures memory-CVE recall while our value moved to protocol-logic; the benchmark drifted from the deliverable  `[PROVEN]` · operational · sharpens rust-mizan-eval

rust-mizan scores recall against a 42-CVE **memory-safety** corpus (UAF blind-spot, OOB, overflow) —
i.e. the *fuzzer* bug-class. But the last several campaigns' accepted advisories were
**protocol-logic** (downgrade, missing-guard, silent-loss, resource growth), a class the benchmark
contains zero of. We are optimizing and reporting a metric for a class we largely stopped hunting, so
a "good recall" number no longer predicts campaign value.
- **Change:** add a protocol-logic slice to the eval corpus (seeded downgrade / enforcement-asymmetry
  / silent-loss / protocol-resource-growth cases with known ground truth) and report recall per
  bug-class, so the metric tracks what the pipeline actually delivers. Until then, don't cite
  memory-CVE recall as evidence of protocol-target readiness.

### L45 — In a LAYERED ecosystem, hunt the SHIPPING integration layer first; it gates reachability for everything below it  `[PROVEN]` · principle · sharpens-L39 / ADR-1

We went to h2 (HTTP/2 core) before hyper (the HTTP layer that ships to axum/reqwest/tonic). hyper's
config then neutralized an entire embargoed h2 finding-cluster (it overrides the relevant protocol
default, so those bugs are unreachable through hyper), and hyper's own 8.7k-LOC HTTP/1 framing (`proto/h1` —
the real request-smuggling surface; httparse only tokenizes header bytes) sat unexamined. Inner-first
costs twice: (a) you find bugs then discount them by the outer layer's config (wasted calibration —
exactly what happened to h2 A/B/C), and (b) you miss the outer layer's own novel protein at the seam.
This is NOT "always start outermost" — start at the layer that (i) SHIPS to the ecosystem you care
about and (ii) DEFINES reachability for the layers under it. For TLS that layer is rustls itself
(termination is the outer trust boundary; x509-parser feeds it — we got that order right); for HTTP it
is hyper (we got it wrong, went to h2 under it).
- **Change:** the target-layer router (threat-model Step 1.5) gains a target-ORDERING rule — in a
  known stack (`httparse`/`h2` ← `hyper` ← axum/…; `asn1`/`x509` ← `rustls` ← …), pick the shipping
  integration layer FIRST and treat the inner crates as reachability-gated by it (compose with L39).

### L46 — A memory/DoS PoC over an in-process mock measures the MOCK's buffer, not the victim's — use a protocol oracle; and verify your own SKEPTICISM, not just the finder's claim  `[PROVEN]` · operational · new

Proving an embargoed HTTP/2 DoS finding (advisory under vendor review), an RSS-based differential
*looked like it REFUTED the bug*: the "control" flood also grew unbounded, so "no differential,
finding dead". Wrong — the control frames were piling up in the **in-process mock's own send-pipe
buffer** (server side), not the client's recv buffer, so only the ATTACK arm's RSS was the real victim
signal. A **protocol oracle** settled it: a diagnostic on a protocol-level signal (not RSS)
distinguished the bounded control path from the unbounded attack path. The finder's claim was RIGHT; my
skeptical REFUTED was the error.
- **Change (two prongs):** (1) for memory/DoS PoCs on an in-process mock, measure a **protocol signal**
  (GOAWAY / WINDOW_UPDATE / RST / a bounded-pipe stall), not just process RSS — RSS is confounded by
  the harness's own buffers, badly when frames carry payload. (2) "panel disposition is triage not
  truth" cuts BOTH ways: verify a REFUTED / your own skepticism against source with the same rigor as
  a CONFIRMED. Here the finder beat the reviewer.

### L47 — Protocol bugs propagate at ECOSYSTEM SEAMS: small crates reduce local complexity, but defaults cross crate boundaries  `[PROVEN]` · principle · sharpens-L45/P4

An embargoed HTTP/2 finding (advisory under vendor review) showed both sides of Rust's "many focused
crates" architecture. On one side, isolating the HTTP/2 state machine in `h2` gives real advantages: a
smaller target, clearer ownership, reusable protocol logic, and a place where one upstream fix can
protect many applications. On the other side, the bug did **not** behave like one isolated consumer
bug. A safe integration layer (`hyper`) neutralizes the class for its users by overriding a
security-relevant default, but direct `h2` consumers and fork-stack clients repeatedly inherit the
core crate's less-safe default. The same state-machine defect then appears as an ecosystem pattern
across many direct-consumer and fork clients.

The lesson is not "small crates are bad". The lesson is that **security-relevant defaults are part of
the API surface once a crate becomes protocol infrastructure**. A safe integration layer can make a
core bug practically unreachable for a large slice of the ecosystem; adjacent consumers that bypass
that integration layer can silently re-open it. This is why a maintainer-grade audit should report the
root cause and the integration matrix separately: root fixed in one place, reachability governed at
many seams.

**Sharpening — the secure default is at the wrong layer.** The deeper fault is not that consumers
"forgot" to override the default; it is that the *safe* default lives in the integration crate
(`hyper`) while the *dangerous* default lives in the protocol crate (`h2`). The safety knowledge
accumulated at the seam that the protocol crate should own. The **same structure recurred in this
campaign's public trailers §8.2.2 finding** (h2 PR #925): `hyper`'s h1 encoder filters
connection-specific trailer fields, but `h2::send_trailers` does not, so the h2 egress seam (and every
direct h2 user) re-opens it. Two independent instances, one shape: **the protocol crate delegates a
security invariant to its callers instead of owning it as a default/invariant, and that delegation is
non-uniform**. So "trust the integration layer" is a fragile safety boundary. The durable fix pushes
the invariant DOWN into the protocol crate (safe-by-default, or enforce on *every* seam), rather than
patching each consumer or trusting one integrator to be complete.
Corollary for disclosure: the consumer/integration matrix is **evidence for the upstream default/
enforcement change**, not a queue of per-consumer advisories to file — filing N consumer bugs treats
symptoms and (see the image-rs SNR incident) burns maintainer goodwill; fixing the seam owner treats
the disease.

- **Change:** for protocol crates with high fan-out, add an explicit **ecosystem seam pass** after the
  root PoC: enumerate top direct consumers and forks, classify each as "protected by integration",
  "direct default inherited", "explicitly disabled", or "public path blocked", then dynamically prove
  the high-risk buckets through public APIs before filing target-specific disclosures.

### L48 — A vulnerability can be introduced and fixed entirely inside an unreleased window; check the actual last-published artifact, not "was it merged + did a release follow", before crediting RustSec eligibility  `[PROVEN]` · operational · sharpens the RustSec Attribution/Timing gates (DISCLOSURES.md's advisory-db queue section)

The ntex `Inner::consumed`-never-resets finding looked RustSec-ready on the strongest possible reading:
our own issue, merged directly by the maintainer, and a new crates.io release (`3.11.0`) cut ~12h
later — a patched version already in hand. Going to actually draft the advisory caught the error.
Diffing the real `3.10.1` (the release immediately prior) against `3.11.0` showed `decoder.rs` had been
substantially restructured between them, and `3.10.1` never had a `consumed` field at all (grepped,
zero hits) — its own bound check (`src.len() >= max_buf_size`) was a per-message check that reset
itself structurally via `src.split_to(len)` on every successful parse, an entirely different mechanism.
The regression we reported was introduced by an internal refactor sometime after `3.10.1` shipped and
fixed before `3.11.0` — that refactor's own first release — ever shipped. No published version was
ever exposed.

**The existing Attribution and Timing gates both said yes here, and both were technically true — and
still missed it**, because neither one asks the actual load-bearing question: did any version a real
user could have installed ever fall inside the vulnerable range? "Merged fix, then a release" is
consistent with two very different histories — a regression caught before it ever shipped, or a bug
that was live in production for months — and both produce an identical merge-then-release timeline. The
two gates can't tell them apart; only the artifact itself can.

- **Change (a third gate):** before filing, diff the last published tarball BEFORE the fix against the
  fixed version (or, cheaper, grep the pre-fix release directly for the vulnerable shape) — don't infer
  exposure from a merge timestamp and a subsequent version bump. No vulnerable shape in any published
  tarball means no affected range and no advisory, however clean the attribution or fast the release.
- **Framed for write-up, not as a miss:** the regression was caught and fixed inside an unreleased
  window — it never reached a real user. That is a stronger outcome than most disclosures ever achieve,
  even though it earns no CVE, no GHSA, and no credit line.

### L49 — Hand-maintained aggregate counts drift; structured data catches what prose review can't  `[PROVEN]` · operational · sharpens L48 / disclosure-tracking hygiene

`DISCLOSURES.md`'s scorecard table drifted at least three times in one working day: a stale header
(date/crate-count/total never bumped after the h2/hyper/Deno filings landed inside its own buckets), a
real double-count the user caught by reading the prose (`actix-web` #4161 named in two buckets at
once), and a self-inflicted reversal on the very fix meant to correct that double-count (the corrected
number was itself wrong, caught only by building a structured export and finding the bucket membership
didn't actually add up). None of these three were caught by re-reading the prose carefully — every one
was caught by turning the same data into a JSON list and counting it with `Counter()`. The fourth error
(the ntex RustSec-eligibility reversal, L48) was ALSO found only once the data had to be represented
concretely enough to draft a real advisory file from it — prose review had already pronounced it
"ready to file," twice.
- **Change:** for any tracker whose headline number is a sum over many hand-classified line items (a
  scorecard, a backlog count, a coverage percentage), maintain the underlying data as structured
  records and compute the aggregate — never hand-type both the classification and the total in prose.
  The same status change propagating across N files (here: `DISCLOSURES.md`, a per-campaign findings file,
  the JSON/CSV export, `DISCLOSURES-PUBLIC.md`) is the same risk at a larger radius — one canonical
  structured source, everything else rendered or cross-checked from it, not independently hand-edited.

### L50 — Attribute to the real PATH/CAUSE, not a look-alike: static (which impl) and dynamic (which panic)  `[PROVEN]` · verify · sharpens L46

Two attribution failures this session, both nearly wrong:
- **STATIC (G1).** I read `headers.remove(CONTENT_LENGTH)` in `role.rs` and cleared the finding as
  retracted — but that code is `Server::parse` (incoming *requests*); the `Client` response path the
  finding is about has no such removal and surfaces the stale CL. A same-named guard in a *sibling* impl
  (Server vs Client, send vs recv) is not coverage of the path under review. The multi-agent matrix even
  carried the wrong read forward — cross-validation catches INDEPENDENT errors (it refuted G2 twice) but
  not a SHARED misattribution, because agents reading the same file share the same wrong impl. Dynamic
  execution on the real `Client` path flipped the verdict.
- **DYNAMIC (cascade).** 6 of 7 crash PoCs surfaced only a downstream cascade panic (a poisoned mutex
  in an unrelated `drop`), masking the ROOT assertion; a source-path first-panic hook was
  needed to attribute to the root, or the breadth evidence was refutable as "you counted cascades."
- **Change:** a clear/retract on a reachable path must name the exact `impl`/role/function actually
  traversed and be confirmed by EXECUTING that path (matrix/agent source-reads are hypotheses until
  executed); a crash PoC attributes to the FIRST panic by source path, not the visible cascade. Both:
  attribute to the real cause, never a look-alike.

### L51 — mirror-walk is a rank-1 (pairwise-semantic) projection; the finder's blind spots are the dimensions it collapses  `[PROVEN]` · principle · generalizes L43 → W20-W28

The invariant-symmetry / "mirror walk" lens (send↔recv, client↔server) is a PAIRWISE-SEMANTIC check, and
every class it missed this session is a dimension that projection flattens: N-ary sink coverage (T — a
guard on 3 of 4 send paths), three-way resource units (D — attacker-spend / charged / retained differ),
temporal repetition (a repeated-event state-machine panic), the translation product
`ingress × egress × position × role` (T-h1 / N-CONNECT), and the orthogonal test-coverage signal (all
three findings sat in empty test cells). It also predicts the NEXT missing lenses by asking what else a
pairwise check collapses: VALUE-RANGE (a guard present but with the wrong threshold) and
ALLOCATION-PROVENANCE (attacker-length → alloc). h2's independently-shipped #909 (HeaderMap panics on
>24,576 header fields) is exactly that value-range/resource class our pairwise lens is shaped not to see.
- **Change:** treat the finder's coverage as the SET OF DIMENSIONS it enumerates, not the set of bugs it
  happens to notice. Add one lens per collapsed dimension (W20-W25, W27), select the emphasis by project
  type (W26), and emit a coverage manifest naming the dimensions NOT walked — turning silent "audited"
  into explicit "these axes unassessed."

## L52 — A status field must describe the artifact it claims to, and "partial" must be a first-class state `[PROVEN]` · instrumentation · extends "no silent skip"

- **Evidence:** bringing up the `sast-driven` tool image produced FOUR distinct defects that are all one
  species — instrumentation reporting on a *proxy* rather than on the thing itself
  (`docs/case-studies/sast-driven-bringup.md`):
  1. ast-grep marked `empty` while holding 87 KB of results — status was computed **before** the
     post-hoc copy that produced the artifact.
  2. Dylint marked "prebuild failed" when the build had **succeeded** — the copy globbed the wrong
     directory, and the copy's outcome was read as the build's.
  3. The clippy lint catalogue passed its guard with **4** of ~800 lints — the guard tested
     *emptiness*, and 4 is not empty. Every hit then came out `unattributed`.
  4. **The costly one:** clippy silently truncated its scan on both large crates — aborting on an
     unrelated example (hyper) and on `#![cfg_attr(test, deny(warnings))]` escalating our added `-W`
     lints into errors (h2) — yet reported `ok`, because the invocation is a PIPE
     (`cargo clippy | clippy-sarif`) whose exit code is the *last* stage's, and `clippy-sarif`
     succeeds happily on truncated input. `pipefail` was set in the runner but each engine runs via an
     inner `sh -c` that does not inherit it.
- **Why it matters more than a normal bug:** defect 4 produced a *confident wrong number*. The 6×
  hits/kLOC spread between h2 and hyper looked like a real property of the code and had a plausible
  story attached (lint hygiene) — it actually measured **when each abort happened**. Had it entered the
  prune ledger, rules would have been dropped on an artifact of compile order. A silent skip announces
  itself as a zero; a silent TRUNCATION announces itself as a plausible measurement, which is worse.
- **Change:** three rules for any tool-integration harness.
  (a) **Assert on the artifact the status names** — did the scan *complete*, not did the last process
  exit 0; does the catalogue hold a *plausible* count, not a non-zero one. (b) **Add `partial` to the
  status vocabulary** and surface it separately (`engines_partial`), because "ran but incomplete" is a
  real state that neither `ok` nor `error` expresses, and its counts must never enter a cross-target
  comparison. (c) **Distrust every pipe**: a pipeline's exit status describes its last stage only, and
  `set -o pipefail` does not cross an inner `sh -c`. Grep the tool's own stderr for its abort
  vocabulary instead. Composes with L50 (attribute to the real cause, not a look-alike) — same failure,
  one layer down in the instrumentation.

## L53 — Two static engines are worth having only when their blind spots are *structural and disjoint* `[PROVEN]` · tooling · refines L51

- **Evidence:** the same six mechanism classes were written twice — once as 54 ast-grep rules, once as
  8 CodeQL queries (`rules/codeql/rust/`) — and A/B'd on identical crates plus a fixture whose answers
  are in the function names (`docs/sast-layer.md` §10.1). Neither dominates, and the split is not close:
  CodeQL sees mutual recursion ast-grep **cannot express at all** (no call graph), cuts unguarded-pop
  volume 41 → 15 with every drop verified arity-correct, and separates `Path::join` from `slice::join`
  by resolved impl path — the FP the pattern rules document as unfixable without types. ast-grep holds
  serde re-entrancy **6/6 vs 0/6** (re-entry crosses a caller-chosen generic, so the call graph breaks
  exactly at the interesting edge) and every `vec!`-shaped allocation, including the ground-truth lopdf
  site, because **`vec!` expands 0/285, 0/93, 0/15 times** — the size expression is not in the database
  at all.
- **Why it matters:** the tempting read of a two-engine result is "keep the better one." That read is
  wrong here and would have cost real recall in both directions. The failures are properties of what
  each engine *represents* — patterns have no types or call graph; QL has no unexpanded macro — so no
  amount of rule work moves them. Complementarity, not quality, is the thing to measure, and it is only
  visible if the same ground truth is run through both.
- **The trap underneath:** the earlier probe nearly killed the port on a **misread counter** — "85 files
  extracted with errors" counts files with ≥1 failed macro expansion, not dropped files; measured
  coverage was 101/101, 36/36, 33/33 with zero `Unextracted` elements. A number that sounds like
  coverage loss was not, while the number that *was* broken (macro expansion) had no alarming name.
- **Change:** (a) when adding a second engine, the acceptance test is a **per-class A/B on ground truth
  we already own**, not a volume or FP comparison; (b) every engine gets a **coverage query that runs
  before any zero is trusted** — for CodeQL that is `ExtractionCoverage.ql`, and it is mandatory,
  because both of its failure modes (macro opacity, unresolvable `cfg` arms) are silent by construction,
  which is L52's duty carried into a second tool; (c) route by class, keeping each engine authoritative
  where it measurably wins.
- **Addendum 2026-07-29, from re-grading all classes against all engines (W34/E8):** grade is a
  property of the **(class × engine) pair**, never of the class — 7 of 9 classes graded differently
  across engines and four inverted outright. The consequence worth carrying: **a "reasoning-only"
  classification is a standing request for a missing instrument, not a closed boundary.** Unwind-safety
  was N under both static engines until Miri was wired, at which point it became the most *decisively*
  gradeable class in the set. So when a class is marked unreachable, record *which instruments were in
  hand when that was decided* — otherwise the mark outlives its own evidence and a future round never
  retries it.

## L54 — A rule pack dense enough to cover the file cannot be said to point at anything `[PROVEN]` · measurement · the negative result W33 was built to find

- **Evidence:** 628 vulnerable/patched crate pairs harvested from `rustsec/advisory-db`, scored two
  ways (`docs/sast-experiments.md` E7/E7b/E7c). Count-level: **84 % of rule×pair cells fire identically
  on both versions.** Site-level, restricted to the 125 pairs whose fix region covers ≤2 % of the crate:
  the pack lands on the fix at **0.97× chance** — enumerators 0.98×, candidate rules 0.94×,
  class-matched 0.82×. Every earlier score for these rules came from our own 58 findings, i.e. the set
  they were derived from; this is the first corpus that could falsify them, and it did.
- **The mechanism is density, not aim.** The pack places a **median of 396 hits per crate**. At that
  rate a tight fix region is covered by construction and there is no aiming left to measure. The one
  rule that does discriminate — `rip-alloc-sized-by-parsed-length`, 11.1 %, ~10× the pack — fires about
  15 times in the entire corpus. Selectivity, not suppression, is the axis: a rule with hundreds of
  hits per crate and a rule with tens are *different instruments* and must not share one pack under one
  promise.
- **I got the headline wrong first, in the flattering direction.** The initial computation reported
  **4.01×**. The null had used `k = number of distinct rules that fired`, when the correct `k` is the
  **number of hits placed** — each hit is an independent draw at the target. Correcting it moved
  expected from 17.2 % to 71.3 % and the lift to chance. A second error rode along: the class-matched
  row was scored against the all-rules null, printing a meaningless 0.24×.
- **Change:** (a) any "better than chance" claim states its null **and the null's `k`**, and `k` counts
  draws, not instruments — a lift computed against an understated null is worse than no lift, because
  it is quotable; (b) every subset gets **its own** null, never the parent's; (c) when a detector's hit
  density approaches the size of the region being tested, report **hits/kLOC first** and treat recall
  as uninterpretable until density is stated; (d) score rules on a corpus they were **not** derived
  from before believing any number about them. Composes with L46 (a plausible measurement that measures
  something else) and L52 (a status describing the wrong artifact).

## L55 — A SAST rule is a scope-narrower, not an oracle; measure it on enumeration, credit the finder honestly `[PROVEN]` · measurement · funnel-attribution

- **Evidence:** E13 (`docs/sast-experiments.md`) folded into `findings-ledger.jsonl` gives the clean
  split: **305 SAST cells → 7 rule-hits (`tp`) / 298 fp / 24 found-alongside (`other_defects`)**, i.e.
  **rule precision 2.3 %.** A per-crate identity check (`count(ledger e13) == count(other_defects)`
  for all 12 crates, `tp` counted-but-never-listed) proves **0 of the 24 ledger findings were
  rule-hits — every one was found by a reasoning agent triaging a cell the rule got wrong.** Combined
  with Chrome (34 SAST cells, 0 recorded hits): **reasoning found 45 of 52 real findings; the SAST rule
  found 7.**
- **Why, structurally:** verification traces **bottom-up — from the sink backwards through its callers
  to the trust boundary** — and that reachability trace is load-bearing. A pattern rule has no call
  graph or dataflow, so it cannot decide reachability; a rule that poses as an oracle ("this is a bug")
  is capped near chance. A rule that is a good **sink-enumerator** (flag the `vec![0; len]` sites, the
  recursive parse fns, the unchecked index sites — and little else) hands the reasoning layer a bounded
  worklist to trace up. That is measurable and it is what enumeration (U1) is for. This is the same coin
  as L54: density is not aim; a pack with 396 hits/crate has narrowed nothing.
- **Change:** (a) score SAST rules on **enumeration** — does the flagged set CONTAIN the real sink sites
  at a small FP multiple (sink-recall × set-tightness) — never on precision-at-the-bug; (b) `found_by:
  sast-driven` means the *pass* found it; the `sast_enumerated` field carries whether the *rule* did
  (`site-hit`/`adjacent` = rule-hit; `site-missed`/`misdiagnosed` = found-alongside) — keep them
  distinct and never fold a "SAST precision" over the pass; (c) `scripts/lens_stats.py` now enforces
  both: per-campaign-class split (reasoning is the only refutation-tested precision), SAST rule
  precision from the E13 artifact reported separately, `latent-hardening` excluded from every precision
  denominator. Composes with L54 (density≠aim), L38 (isolate the corpus), and the funnel discipline in
  `docs/mechanism-effectiveness.md`.

## L56 — For low-severity findings, default to issue + a suggested-fix comment, not a full PR `[PROVEN]` · disclosure-relations · maintainer-stated

- **Evidence:** quick-xml PR #982 (serde recursion-depth fix). Our account posted an honest, humble
  note (security researcher, LLM-assisted, ~50 concurrent issues, motivation = Rust-infra security)
  and explicitly *asked the maintainers* what workflow they prefer. Maintainer `dralley`'s reply:
  "For a low severity issue like this, if you don't have the time required to actually commit to
  understanding the fix and the PR, it's fine to just report IMO. Perhaps with a suggested plan of
  action as a followup comment on the issue." Both underlying bugs (#978 serde recursion, #980
  `resolve_prefix` O(depth²)) were then **fixed by the maintainer's own commits** and closed — a win —
  while our PR #982 was closed unmerged (superseded). Net: the issues were valued; the *PR* was the
  friction.
- **Why:** a PR is a promise to shepherd and defend a fix through review; for a low-severity
  availability bug that promise costs the maintainer review time and costs us bandwidth we don't have
  at 50-issues-scale. An issue that states the bug + a concrete suggested fix (as prose or a small
  diff *in the issue body/comment*) gives the maintainer everything to act on with none of the
  PR-review overhead, and lets them implement it their way (which they did, better-scoped, e.g. #980's
  `max_namespace_bindings` cap replacing a per-element limit). This is the constructive, maintainer-
  stated version of the image-rs pushback ([[image-rs-maintainer-pushback]]): the volume/PR-shape was
  the irritant, not the findings.
- **Change:** (a) default artifact for a **low-severity** finding = **issue with a suggested plan of
  action / fix sketch as a comment**, NOT a full PR; file a PR only when the fix is non-obvious AND we
  will commit to shepherding it, or the maintainer asks for one. (b) When disclosure volume is high,
  say so plainly and *ask the maintainer their preference* — the honest ask itself de-escalates (it
  did here). (c) Medium+/security-relevant or a one-line obviously-correct fix still merit a PR. This
  sharpens P1.6 (`disclose` stage): the stage should pick issue-vs-PR by severity, defaulting low-sev
  to issue-only. Composes with L34/L35 (maintainer comments are data, verify silent fixes) and L13
  (adversarial maintainer-eye pre-disclosure review).

## L57 — Verify every finding against the LATEST published release, not the analysis snapshot `[PROVEN]` · disclosure-hygiene · sharpens L15

- **Evidence:** find011 — `http` `PathAndQuery` `u16` index-truncation, surfaced by the SAST-driven
  pass on a corpus snapshot pinned to `http` 1.4.2 (cell `http@2178e175/…/uri::limit-pair`), triaged
  3-0, and PoC'd end-to-end against real `h2` 0.4.15 (both a remote panic and a path/query desync).
  Only when the PoC was re-run against the newest published crate did it reclassify: `http` 1.5.0
  (2026-07-29) had already added the `bytes.len() > MAX_LEN` guard in `scan_path_and_query`
  (path.rs:478-480) with regression tests, and the PoC returns `InvalidUri(TooLong)`. The bug was real
  on the snapshot and dead on latest.
- **Why:** the analysis snapshot is a fixed point in the past; a finding true there can be fixed by the
  time you verify it. Reporting against the snapshot version would have put a would-be flagship 0-day in
  front of a maintainer who fixed it weeks ago — the exact low-signal contact that draws pushback
  ([[image-rs-maintainer-pushback]]). Re-running the PoC against the latest release is a one-command
  gate that *reclassifies* the finding (0-day → already-fixed) BEFORE any external contact, which is a
  disclosure-quality win, not a loss.
- **Change:** the pre-disclosure gate must build+run the PoC against the current published version(s),
  not only the snapshot; a finding that does not reproduce on latest is marked fixed-upstream and never
  routed to a maintainer report. This extends L15 (verify against release AND master) from "read the
  code" to "run the PoC on the shipped artifact." Composes with L58.

## L58 — Trace every "discovery" to its source before disclosing — a real finding can be a public rediscovery `[PROVEN]` · disclosure-hygiene · extends L15/L16/L57

- **Evidence:** find011 again. After L57 showed it was fixed in 1.5.0, tracing the fix (`scan_path_and_query`
  guard) led to PR [#856](https://github.com/hyperium/http/pull/856), which closed issue
  [#855](https://github.com/hyperium/http/issues/855) — opened by a third party (`hey-jj`, 2026-07-25),
  describing the SAME bug with the SAME two impacts we found (DoS panic in the accessors + path/query
  desync, verbatim "proxy authorization bypass — `path()` sees `/` while forwarding the real path").
  Our run (2026-08-03) was an independent-but-9-days-late rediscovery of a public, already-fixed report.
  A CHANGELOG/release-code check alone (L57) would have caught "fixed" but not "already publicly
  reported with full security analysis"; only tracing the fix to its issue revealed that a new issue
  would be pure duplicate noise.
- **Why:** "not in the latest release" and "not already known" are different facts. A silent-fix check
  stops at the code; the issue tracker and advisory DBs are where you learn a human already filed it.
  Opening a new issue on top of a closed, fully-analyzed report is exactly the low-SNR move to avoid,
  and it misattributes credit. Conversely, this does NOT diminish the pipeline result: find011 came
  through the full SAST→prioritise→finder→triage→PoC chain with no knowledge of #855, so a late
  rediscovery of a real, security-confirmed bug is honest evidence of recall — just not a disclosure.
- **Change:** before drafting ANY disclosure artifact, trace the finding to its source: grep the
  upstream issue tracker (open AND closed), release notes/CHANGELOG, and CVE/RustSec/GHSA for the
  crate + symbol. If it is already reported/fixed, stop — the finding stands as a recall data-point, not
  a disclosure. Any residual action is limited to a genuinely-missing advisory, and must reference the
  original report and credit its reporter. (Whether to automate this cross-check is scoped in
  IMPROVEMENTS.md W47.)

## L59 — Environment traps are a deploy-layer GATE, not a runtime surprise — canary the daemon before the hour-long build `[PROVEN]` · deploy-hygiene · extends L28

On a hardened box (docker with `userns-remap` + `containerd-snapshotter` + `iptables: false`), building
the SAST tool image failed THREE different ways, each discovered only after paying for it: (1) no
container egress — `apt-get` could not resolve `deb.debian.org`, surfaced at build step 5; (2) a
pathologically slow OPTIONAL engine (dylint's `general` lints) — 60+ minutes on a single step; (3)
`failed to export layer: host ID 0 cannot be mapped`, at the very end, after every compile had already
finished. Each is a *property of the daemon*, knowable in seconds: a 3-line `FROM busybox` + `touch
/root/probe` build settles the export trap; a `docker run <img> curl deb.debian.org` settles egress. The
export canary in fact returned PASS — proving the earlier failure was the huge dylint layer specifically,
not a fundamental block. That is exactly what a cheap probe tells you and an hour-long build does not.
- **Why:** "raw tool output is never a gate" is already doctrine; the same logic applies one layer down.
  An environment that cannot build+export an image, cannot give a container egress, or leaves root-owned
  litter the operator cannot delete (L28) will waste the whole run — and the failure surfaces at the most
  expensive possible moment (export, after all compiles). A ~10-second gate turns an hour-long faceplant
  into an immediate, named diagnosis with a remediation.
- **Change:** `scripts/preflight-deploy.sh` runs BEFORE any containerized build/scan (wired into
  `docker/sast/sast-scan.sh`): image-present (image-is-gone), export-canary (userns/containerd
  root-ownership trap), egress-canary (iptables/NAT/DNS), result-writeback (L28 root-owned litter). Each
  failure prints a specific remediation and aborts. Generalizing it to every container mode is W48.

## Suggested next actions

The original cheap honesty gates are implemented for the Rust baseline. The
authoritative current order now lives in [`IMPROVEMENTS.md`](IMPROVEMENTS.md):
live W2b verification, credential separation (W3), first-class variant-scan
(W2), then the protocol-logic lens/oracle/evaluation work (W9–W12), and the
h2/hyper-arc refresh (W13–W19), and the finder-mechanism block (W20–W28: dimensional lenses,
project-type emphasis packs, SAST-as-engine — see L50/L51).
