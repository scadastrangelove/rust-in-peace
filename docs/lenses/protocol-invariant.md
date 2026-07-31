# Finder lenses for protocol / state-machine / API-contract targets

Two review-brief lenses for the `vuln-scan` fan-out, added when the threat model stamps
`target_layer: protocol-state-machine` or `api-contract` (see [`docs/DECISIONS.md`](../DECISIONS.md)
ADR-1, `LESSONS.md` L43). They target the class a crash-hunting fuzzer cannot reach: a guard present
in one place but missing at its mirror, and a value that is validated and then silently discarded.
Drop either block in verbatim as a subagent's review brief; each returns candidates in the standard
`F-NNN` shape (file:line + title + evidence + why-real).

Both are **grounded**, not hypothetical — the invariant-symmetry examples below are real rustls
findings filed 2026-07-23 (GHSA-j99h-2h74-pcqx, GHSA-4xwv-fw6q-5gvr).

---

## Lens 1 — invariant-symmetry (the "mirror walk")

**Premise.** A protocol enforces invariants ("QUIC uses TLS 1.3 only", "a QUIC suite must be
QUIC-capable", "chunked framing terminates on a zero-size line", "recursion is bounded"). Bugs cluster
where an invariant is enforced in one place but **not at its mirror**. The control-asymmetry *is* the
finding — you do not need a crash.

**Procedure.**
1. **Enumerate the invariants.** From the spec/RFC and the code's own comments/error variants, list
   the rules the implementation must uphold. Grep the error enum (`PeerMisbehaved`, `PeerIncompatible`,
   `AlertDescription`, `Error::…`) — each variant names an invariant.
2. **For each invariant, locate every enforcement site** (`grep` the guard: the `is_quic()`,
   `usable_for_protocol(...)`, the `if version != …`, the bounds/limit check).
3. **Walk the four mirror axes** — for each enforcement site ask "where is the mirror, and is it
   guarded the same?":
   - **client ↔ server** — the server rejects X; does the client? (rustls B: server rejects
     TLS1.2-on-QUIC twice; the client accept path has no `is_quic()` guard.)
   - **send ↔ receive** — the outgoing value is filtered; is the incoming one re-validated? (rustls A
     client path: the outgoing ClientHello is suite-filtered by `usable_for_protocol`, but the
     acceptance of the server's chosen suite checks provider-membership only, not offered-ness.)
   - **offered ↔ accepted** — we constrain what we offer; do we constrain what we accept back?
   - **one-param ↔ all-params** — one negotiated parameter is validated (suite); are the siblings
     (version, kx-group, ALPN)? Missing siblings travel in packs.
4. **Release-diff each candidate.** Diff the pin against the latest released tag: a guard **present in
   the release, dropped at the dev pin** is a *regression* (rustls A server path: `usable_for_protocol`
   filter existed at `server/hs.rs:601` in v/0.23.42, gone in 0.24-dev). This sets severity and
   disclosure channel — record it.
5. **A guard with no mirror is a candidate** — even with no crash. Emit it with the two sites
   (enforced-here `file:line`, missing-there `file:line`) as the evidence.

**Output per candidate:** `{ invariant, enforced_at: file:line, missing_mirror_at: file:line,
mirror_axis, release_status: shipped|dev-new|dev-regression, downstream: <panic|silent-loss|
downgrade|…> }`.

---

## Lens 2 — silent-failure differential (control-vs-attack)

**Premise.** The bug is *not* a crash: a validated, decrypted, or parsed value is **silently
discarded** or a message that should be rejected is **accepted**. A coverage-guided fuzzer has no
oracle for this; you build the oracle as an A/B where **only one variable changes**.

**Procedure.**
1. **Spot the shape.** Look for: a `match … { Ok(_) => {} … }` that drops a payload; a value computed
   then not threaded to its consumer; an accept path that lacks the reject its sibling has; a "return
   the state we reached" that steps *past* the point it should stop.
2. **Build the control and the attack from ONE construction**, differing in a single variable:
   - CONTROL = the benign/separated case (records delivered in separate calls → payload delivered).
   - ATTACK = identical, with the one variable flipped (co-batched into a single call → payload
     silently dropped).
   - Use the target's **own test-helper crate** to reach the state (harness-reuse; rustls: depend on
     `rustls-test` as a git dep and drive real, non-mocked sequences). Do not hand-roll wire format or
     mock crypto if the target ships helpers.
3. **The oracle is the control/attack delta**, not a panic: CONTROL must deliver / reject correctly;
   ATTACK must exhibit the loss / wrong-accept. Exit 0 iff both hold, non-zero otherwise, so the PoC
   doubles as a regression test.
4. **Rate honestly.** Silent loss on an unreleased API is a correctness bug, not a security advisory;
   accept-what-should-be-rejected on shipped code with a real attacker is not. State exactly what the
   PoC demonstrates vs. what is inferred (rustls B: acceptance demonstrated at the API; network on-path
   reachability inferred from QUIC Initial packets lacking integrity protection, not exercised).

**Output per candidate:** `{ site: file:line, discarded_or_accepted: <what>, control: <benign case>,
attack: <one-variable flip>, demonstrated: <exact>, inferred: <exact>, class: silent-loss|
wrong-accept }`.

---

## Notes

- These lenses find **candidates**, not verdicts. Every candidate still goes through adversarial
  verify + release-diff + precondition tracing; the finders over- and under-claim, and that calibration
  layer is the value-add on mature targets (`LESSONS.md` L43, and the rustls campaign's two correction
  rounds).
- If the target is `data-format parser`, do **not** run these — route to fuzz-first (ADR-1). If it is
  multi-layer (protocol core + a `msgs/` byte-parser), run these on the protocol surface and fuzz the
  parser sub-surface.
- Harness-reuse (step 2 of Lens 2) is the highest-yield PoC method for both lenses: the target's
  internal test crate gets you to deep protocol states a fuzzer can't, and produces decisive,
  non-mocked PoCs.
