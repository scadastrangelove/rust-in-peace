# Cross-cutting methodology — Architecture Decisions (ADR)

Global, technology-agnostic decisions that shape recon, threat modeling, and tool selection across
**all** targets. Per-profile decisions live in `docs/profiles/<profile>/DECISIONS.md`; the
generalizable *how-to* lives in [`docs/extending.md`](extending.md). This file records the
cross-cutting **why**. Each ADR notes where it is realized.

---

## ADR-1 — Route target → bug-class → tool by the target's LAYER; fuzzing is layer-gated, not the default

**Decision.** Classify every target into one of three layers **before** hunting, and let the layer
pick the primary bug-class and primary tool:

| Layer | Examples | Primary bug-class | Primary method |
|---|---|---|---|
| **data-format parser** (bytes → structure) | image, pdf, font, ELF/Mach-O, codec | panic / OOB / overflow / alloc-DoS on malformed input | **fuzz-first** |
| **protocol / state-machine** | TLS, QUIC, HTTP framing, handshakes, sessions | missing/asymmetric enforcement, downgrade, state-transition data-loss, protocol-tied resource growth | **invariant-first** |
| **API-contract / library surface** | serialization, containers, config, fs helpers | contract violation, silent failure, spec/impl divergence | **differential-first** |

Fuzzing runs when **all** hold: the target (or a sub-surface of it) is a parser **and** it is not
already well-covered by OSS-Fuzz **and** the target class is crash/OOB/alloc. Otherwise deprioritize
naive byte-mutation fuzzing — it is the wrong tool for the other two layers.

**Why.** The recent up-stack arc — rustls (GHSA-j99h, GHSA-4xwv), quinn-proto (GHSA-hmxj), gitoxide
(GHSA-pmm9), ciborium, actix/ntex — delivered **all** of its value from semantic/protocol bugs found
by threat-model reasoning + differential/asymmetry review + harness-reuse PoC, with **fuzzing unused**.
That was not neglect; it was correct tool-selection, for three structural reasons:

1. **Reachability.** A protocol bug lives deep in a valid multi-step handshake/state sequence a
   mutation fuzzer almost never constructs; the parser bug lives one malformed record away.
2. **No crash oracle.** The protocol-layer bug is frequently *not a crash* — silent data loss,
   accept-what-should-be-rejected, a downgrade. Coverage-guided fuzzing has nothing to latch onto.
3. **Domain-specific invariant.** The violated rule ("QUIC uses TLS 1.3 only") is semantic and is not
   encoded as an assertion the fuzzer can trip.

Add **OSS-Fuzz redundancy**: rustls/quinn ship their own fuzz corpora, so our fuzzer mostly
re-finds what their CI already covers — the marginal value is precisely in the classes their fuzzing
does *not* reach. By contrast the earlier parser arc (zune-jpeg, png/image, miniz_oxide, object,
lopdf) delivered from fuzz-found panic/OOB, exactly as this routing predicts. See [`LESSONS.md`](../LESSONS.md)
L42.

**Practical consequence.**
- The **threat-model skill** runs a layer-classification step (Step 1.5) that stamps the target's
  layer and emits the per-layer hunt plan.
- Protocol/API targets add two finder lenses (see `docs/lenses/protocol-invariant.md`):
  **invariant-symmetry** — for every guard/check, locate its *mirror* across client↔server,
  send↔receive, offered↔accepted, one-param↔all-params; a control-asymmetry is itself the finding
  (rustls A/B); and **silent-failure differential** — a control-vs-attack (or spec-vs-impl) oracle,
  because these bugs don't crash (rustls C). See LESSONS L43.
- The high-yield PoC method for protocol targets is **harness-reuse**: depend on the target's own
  (often unpublished) test-helper crate and drive real, non-mocked sequences to the exact state where
  the invariant is checked — decisive, and far cheaper than fuzzing to reach that state.
- Fuzzing is **not retired**. It stays the right tool for parser targets, and the way to bring it
  *up-stack* is **differential fuzzing** (impl-vs-impl / impl-vs-oracle) and **stateful/grammar
  fuzzing** that can build a valid handshake — never naive byte-mutation. This is a pipeline
  investment (`IMPROVEMENTS.md` W11), not a default.
- **Release-diff is mandatory** for reachability rating on any target: a defect at a dev pin may be
  dev-only-new, a dev *regression* of a guard present in the last release, or shipped. This
  reclassified all three rustls findings and flipped their disclosure strategy — diff the pin against
  the latest released tag before rating or routing. (Composes with L39.)

**What this does NOT change.** Severity is still calibrated by measured impact and precondition, not
by mechanism-match; "0 findings" on a mature protocol target remains an honest, expected outcome.
The routing decides *where to look and with what*, not *how loudly to claim*.

---

## ADR-2 — Static analysis enters as an *enumerator*, a *filtered candidate feed*, and *signature memory* — never as a finding and never as a gate

**Decision.** Add a static-analysis (SAST) layer with four roles, each with its own success criterion,
and a hard rule that raw tool output never crosses into the finding path:

| role | output | optimize for | who consumes it |
|---|---|---|---|
| **U1 enumerator** | a *site inventory* (worklist) | **completeness** | the finder lens (W20–W27) — it makes the mirror-walk exhaustive |
| **U2 candidate feed** | clustered *cells* | precision **after** filtering | the finder, as additive focus material |
| **U3 signature memory** | rules distilled from our own findings | cross-target reuse | every future **and past** campaign (retro-scan) |
| **U4 negative memory** | machine-checkable suppressions | never re-litigating a refutation | triage / verify |

Every candidate that originates in a SAST hit still goes through the unchanged union-of-N →
3-skeptic verify → independent-PoC gate. No hit becomes a finding, a report line, or a merge gate.

**Why.** Two reasons, one diagnostic and one economic.

1. **`LESSONS.md` L51** — the finder's mirror-walk is a rank-1 (pairwise-semantic) projection, and its
   blind spots are the dimensions it collapses. W20–W27 restore those dimensions as *prose lenses*,
   which cannot be exhaustive (an "enumerate every enforcement site" instruction becomes a hand-`grep`
   of the shapes the agent thought of) and cannot be regression-tested (a lens that silently stopped
   working produces the same output shape as one that works). A rule file is exhaustive by
   construction and scoreable against a corpus with known answers. **The agent stays the comparator;
   the rule becomes the enumerator.**
2. **A finding is currently a one-shot asset.** Its pattern lives on as prose in `LESSONS.md` and in
   the `/variant-scan` CVE pass, which re-derives it every run and forgets it afterwards. Distilled
   into a rule, the same knowledge re-runs on ~20 already-pinned crates at grep cost — **every new
   rule is instantly a 20-target variant sweep** ([`variant-analysis.md`](variant-analysis.md)'s P7,
   made persistent).

**Practical consequences.**
- **Tool tiering by build requirement, not by capability.** Tier-P (pattern engines: OpenGrep,
  ast-grep, CodeQL's `build-mode: none`) read source. Tier-C (clippy, Dylint, MIRAI, lockbud, Miri)
  require a compile, and **compiling an untrusted crate executes its `build.rs` and proc-macros**.
- **Packaged as one target-independent tool image**, `vuln-pipeline-sast:<pack-rev>`, built by the
  same shared-base idiom as `agent_image.py` — but mounting the target source read-only instead of
  `COPY`ing a crate in, since it serves every target. Everything runs in-container under gVisor with
  `--network none`; deps arrive via an orchestrator-side `cargo fetch --locked` (downloads, does not
  build) mounted read-only. This keeps both invariants — untrusted code never executes outside the
  sandbox, the sandbox never gets network — and makes the tiering an implementation detail rather than
  a rule the operator must remember. It also pins the score key: `(corpus_rev, image_digest,
  rule_pack_rev)`, which is what makes "did the rule pack improve?" answerable at all. High-FP
  nightly tools (MIRAI, lockbud) live in a separate shadow-track image; Rudra is used as upstream's
  frozen image, offline. See [`sast-layer.md`](sast-layer.md) §8.3.
- **Routing reuses what exists**: ADR-1's `target_layer` picks the emphasis (protocol → U1-heavy;
  parser → U2-heavy), `capabilities.json` picks the classes. This is IMPROVEMENTS **W26**'s
  emphasis-pack idea made executable.
- **Two tracks, as in the WAAP rule-mining discipline**: `shadow` rules run but feed cells only;
  `active` rules may produce candidates. Promotion is by *measured* precision (or, for enumerators,
  measured completeness) on our own labeled corpus — which is why **`corpus/findings.jsonl` is the
  prerequisite for everything else**, not an afterthought.
- **Every rule is born with a test** — the seed site must match (positive) and its *guarded siblings*
  must not (negative). This forces the rule to encode the guard, not just the dangerous shape;
  without it a rule is a `grep`. (Applies to rules we *author*; see the v1 amendment below for what
  runs first.)
- **v1 amendment — PRUNE, don't PICK (2026-07-28).** The first implementation does **not** start from
  hand-authored rules. It runs **every engine's default rule set out of the box** — upstream
  semgrep-rules, the trailofbits pack, clippy with *all* groups incl. pedantic/nursery, dylint's
  `general` library, cargo-audit — and then prunes what does not pay, from **measured yield per rule
  and per group** across ≥3 crates. Rationale: hand-picking rules up front is guesswork wearing a lab
  coat — it just moves the unmeasured judgment earlier. Taking everything and pruning on data costs
  one noisy first run and produces a defensible rule set. The consequence for tooling is that each
  hit must carry its engine + rule id + lint *group*, which is why the image catalogues clippy's
  lint→group table at build time. Authored/distilled rules (§6) still come, but *after* the vendor
  baseline has shown where the gaps are.
- **Additive, never restrictive.** SAST cells enter finder briefs as "attend to…", never "look only
  at…". If the blind pass's unique-finding rate drops after this lands, that is a regression.
- **CodeQL is BYOL**: queries only in-repo, triple-explicit activation (flag + binary present +
  operator attestation), and downstream artifacts must be schema-identical whether it ran or not.

**What this does NOT claim.** No SAST finds this arc's headline bugs — h2 trailers §8.2.2, the
rustls QUIC downgrade, and two still-embargoed HTTP-stack findings are all
PROTOCOL-LOGIC, where the defect is a disagreement between two parsers or a missing mirror of a
semantic invariant. The tooling reference's own PROTOCOL-LOGIC row reads "none — seeds only", and this
ADR agrees. The layer's value on those targets is exhaustive enumeration and durable memory, not
detection. **Experiment E1** ([`sast-layer.md`](sast-layer.md) §11) is designed to falsify this ADR:
if the candidate rules "re-find" the protocol-logic findings, suspect the rule; if the enumerator
shows no residue beyond what the hand-walk already visited, the premise is wrong and the layer should
not be built.

**Realized in.** [`docs/sast-layer.md`](sast-layer.md) (full design), `IMPROVEMENTS.md` **W26–W28**,
`LESSONS.md` **L51**.
