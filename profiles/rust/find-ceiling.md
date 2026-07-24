# The find ceiling: what static should ATTEMPT vs DEFER-TO-DYNAMIC

Static FIND is strong at *reaching* a sink and constructing a hostile **byte**
input; it is weak — sometimes provably weak — at *settling* a class whose trigger
is a hostile **trait impl**, a **concurrent schedule**, an **uninitialized** read,
or a bug behind an un-instrumented **C** boundary. This page is the map that keeps
static from burning effort on classes it cannot close, and routes each one to the
dynamic rung that owns it.

It is the same **"no-crash = missing capability"** rule the fuzz stage uses
([`find-to-fuzz.md` §5](find-to-fuzz.md)), pulled one stage earlier — applied at
FIND, not just at fuzz.

## The principle

> **A finder that cannot reach a class *statically* must DEFER — never return
> CLEAN.** Reaching a sink you cannot reproduce is a *submission*
> (`<defer_dynamic>`), not an acquittal.

Two failure modes this kills:

- **False silence.** "No byte input crashes it" is not "it is safe." For the four
  soundness classes below there *is no byte input* from a static byte-driver — the
  break needs a lying `size_hint`, a panicking `Drop`, a cross-thread send. On the
  rust-mizan corpus those four classes were **8/8 confirmable dynamically** (Miri /
  compile-proof) and **noisy/flat statically** — the same 8/8 the find prompt cites
  as "confirmable dynamically and noisy/flat statically" ([`find_prompt.py`
  DEFER-TO-DYNAMIC section](../../harness/rust/find_prompt.py); [`README.md`
  §"8/8 soundness via Miri/compile-proof"](README.md)). A finder that scored them
  CLEAN would have hidden 8 real bugs.
- **Wasted budget.** Static grinding on a deep structure-gated parser, an MSan-only
  uninitialized read, or a `%n` in un-instrumented C spends the whole budget bouncing
  off the first gate / the wrong oracle. ATTEMPT the part static is good at
  (reachability, locating the sink), then DEFER the confirmation to the tool that
  can see it.

The static ceiling is not "found nothing" — it is a **routed deferral with a
reason**. The reason names the capability static lacks, exactly as
[`find-to-fuzz.md` §5](find-to-fuzz.md) turns a clean fuzz run into a capability map.

## The map — bug class → static verdict → dynamic owner → evidence

`ATTEMPT` = static both locates *and* can validate (craft a byte PoC, or prove by
compile). `ATTEMPT→DEFER` = static locates / proves reachability, but the
*confirmation* needs a specific dynamic oracle. `DEFER-TO-DYNAMIC` = static cannot
reach the trigger at all — emit `<defer_dynamic>`, never CLEAN.

| bug class (CWE) | static verdict | dynamic rung that owns it | evidence from the eval |
|---|---|---|---|
| **UAF / double-free** (416/415) via panic-safety or trait callback | **DEFER-TO-DYNAMIC** | [`adversarial_impl`](harness-templates/adversarial_impl.rs) + **Miri** (Stacked-Borrows / invalid-free); ASan for the heap variant | the double-free needs a `Drop`/`next` that panics *mid*-`ptr::read` — no byte input exists, so a byte-driver reads it flat; Miri flags it precisely, but **only** with an L12 heap-owning element (a `u32` slot makes the double-drop a silent logic error) |
| **higher-order-invariant** — unsafe trusts a lying `size_hint`/`ExactSizeIterator::len`/`Ord`/`Borrow` (662) | **DEFER-TO-DYNAMIC** | [`adversarial_impl`](harness-templates/adversarial_impl.rs) + **Miri** | the validated `SmallVec::insert_many` case (RUSTSEC-2021-0003 class): a ~15-line `Iterator` whose `size_hint()` returns `(0, Some(0))` while yielding one element → OOB `ptr::write`, reproduced under Miri **in seconds** — a bug one-pass blind static scored CLEAN. Byte-fuzzing has no surface (no bytes); on a single-label benchmark such a flag can even read as a "false alarm" while being a real latent bug (cf. rust-mizan vuln-0008) |
| **panic-safety** — unwind through a temporarily-broken unsafe region (416/415) | **DEFER-TO-DYNAMIC** | [`adversarial_impl`](harness-templates/adversarial_impl.rs) + **Miri** | the Rudra class; the invariant break lives *between* two unsafe ops, invisible to a one-pass read. Triage **R10**: this is memory-safety, not "just a panic" — do not close it with the R5 availability lens |
| **Send/Sync variance** — `unsafe impl Send/Sync` w/o the bound (662) | **DEFER-TO-DYNAMIC** | [`sendsync_compileproof`](harness-templates/sendsync_compileproof.rs) (**the compiler** — compiles ⇒ unsound) **or** a threaded driver + **TSan** | one of the four soundness classes — statically it reads as "an `unsafe impl`", which is not itself a bug; the *proof* is whether `require_send::<C<Rc<()>>>()` compiles. Triage **R9**: keep it even with no caller today |
| **unsafe_generic_soundness** — invariant holds for the tested `T`, not every admitted `T` (662) | **DEFER-TO-DYNAMIC** | [`sendsync_compileproof`](harness-templates/sendsync_compileproof.rs) / [`adversarial_impl`](harness-templates/adversarial_impl.rs) under **Miri** | soundness class; static sees the generic instantiated at *one* type and cannot enumerate the hostile `T` (a high-alignment / `!Send` / ZST element). Dynamic instantiates the adversarial `T` and the compiler/Miri settles it |
| **structure-gated parser** — magic/length/frame container (125/787) | **ATTEMPT** reachability, **DEFER** repro | grammar/dictionary fuzz — `#[derive(Arbitrary)]` over the AST + `-dict=` (`grammar_parser.rs`), see [`find-to-fuzz.md` §5](find-to-fuzz.md) | **0040** (ID3/synchsafe): blind **and** coverage fuzzing *both* missed it — a random byte stream never satisfies magic + synchsafe-length (7 data bits per byte, high bit forced 0) + frame gates. Static *can* prove the public wrapper reaches the private sink (0040's `get_id3` via `read_from_slice`); the repro escalates to grammar. Tag it `structure_gated` in `capabilities.json` |
| **uninitialized read** (908) | **ATTEMPT** locate, **DEFER** confirm | [`index_arbitrary`](harness-templates/index_arbitrary.rs) shape under **MSan** (`-Zsanitizer=memory` **+ `-Zbuild-std`**) | **0027**: the memory is *validly allocated*, so **ASan is blind** and a panic-fuzzer sees nothing — a static read-of-uninit trace locates the `MaybeUninit`/`set_len`-gap sink, but only MSan *confirms* it, and only if std itself is instrumented (`-Zbuild-std`, plus a `--privileged`/`--cap-add` container for MSan's shadow map) — an uninstrumented std yields false uninit reports. Emitting CLEAN here (or fuzzing under ASan) is the trap |
| **C-FFI format string** (134) | **DEFER-TO-DYNAMIC** | ASan-on-the-C-dep (built `-fsanitize=address`), else a `%n`/bad-ptr oracle; [`byte_parser`](harness-templates/byte_parser.rs) feeds the `%`-directives | **0033**: a `%n` into `libsqlite3-sys` — the sink is *across* the FFI boundary in un-instrumented C, and the sanitizer that would catch it can't even build (`libsqlite3-sys`'s build script breaks under `CFLAGS=-fsanitize=address`). Static cannot execute C; DEFER with the "instrument the C dep" reason |
| **plain OOB via untrusted index/len** (125/787/129/193) | **ATTEMPT** | [`index_arbitrary`](harness-templates/index_arbitrary.rs) under **ASan** (confirms, not required to find) | static + ASan are **strong** here — a `usize` reaching an unchecked `.offset()`/`get_unchecked`/`ptr::write` is a byte-drivable, hand-craftable PoC. In the eval the races/uninit/leaks that static missed were a *different* axis; this axis static settled directly (e.g. the `Slab` `Index` unchecked-offset → ASan heap-overflow) |
| **arithmetic-overflow → index/alloc** (190) | **ATTEMPT** | [`index_arbitrary`](harness-templates/index_arbitrary.rs), feed the raw size, ASan + overflow-checks | byte-drivable: the overflowing `size*elem` or wrapped counter is a value static can push to the multiply and craft an input for. Triage **R7** gates it — the overflow counts *only* when the wrapped value then indexes/sizes an allocation, which is exactly the ATTEMPT-able case |

## Why the DEFER rows are DEFER — the shared shape

Every `DEFER-TO-DYNAMIC` row fails static for the *same structural reason*: **the
trigger is not in the input, it is in a caller-supplied behavior or a boundary
static can't cross.**

- **No byte input exists** (the four soundness classes). The break needs a hostile
  `Iterator`/`Ord`/`Clone`/`Drop` impl, or an `unsafe impl Send` that only a
  *type* (not a value) can exercise. A byte-driver feeds `&[u8]`; there is no byte
  string that makes a *correct* `size_hint` lie. This is why the eval measured them
  **flat statically** — every run reads the same un-triggerable `unsafe` block.
- **Wrong oracle** (908 uninit, 134 C-FFI). The sink *is* byte-reachable, but the
  effect is invisible to the tool static/ASan can run: uninit-read needs MSan with
  an instrumented std (`-Zsanitizer=memory -Zbuild-std`, 0027), a C `%n` needs the
  C dep built with ASan (0033). Static locates; the confirmer must switch oracle.
- **Gate too deep** (structure-gated). Reachability is provable statically (public
  wrapper → private sink), but *reproduction* needs the format's grammar, not raw
  bytes (0040).

## How a DEFER is emitted — tie to the find prompt

A finder settles a DEFER row by emitting `<defer_dynamic>` (the find prompt's
**Alternate output**, [`find_prompt.py`](../../harness/rust/find_prompt.py)),
**not** `<poc_path>` and **not** a CLEAN result. The tag is a first-class finding
routed to the dynamic confirmer:

```
<defer_dynamic>
class: unsafe_trait_trust      # unsafe_trait_trust | panic_safety |
                               #   sendsync_variance | unsafe_generic_soundness
sink: <fn (file:line)> — the unsafe op + the trusted callback
why_no_byte_poc: the break needs a lying size_hint / panicking next / cross-thread
      send, not a crafted input file — this driver only feeds bytes.
adversarial_sketch: |
  // element MUST own heap (Box<u32>, not u32) — L12 — or Miri/ASan see nothing
suggested_oracle: miri         # miri | adversarial_impl | tsan | compile_proof
</defer_dynamic>
```

Mapping this page's rows onto the prompt's four `class:` values and the
`suggested_oracle` (both taken verbatim from the find prompt's Alternate-output
block):

| this page's DEFER row | `<defer_dynamic>` `class:` | `suggested_oracle:` |
|---|---|---|
| UAF/double-free, panic-safety | `panic_safety` | `miri` (via `adversarial_impl`) |
| higher-order-invariant (lying `size_hint`/`len`) | `unsafe_trait_trust` | `miri` / `adversarial_impl` |
| Send/Sync variance | `sendsync_variance` | `compile_proof` (or `tsan` for the race variant) |
| unsafe_generic_soundness | `unsafe_generic_soundness` | `compile_proof` / `miri` |

The `ATTEMPT→DEFER` rows (structure-gated repro, uninit-confirm, C-FFI) are *not*
one of the four prompt classes — static submits a normal reachability trace (or a
partial finding) and the **reason** rides into [`find-to-fuzz.md` §5](find-to-fuzz.md)'s
capability map, which picks the escalated rung (grammar / MSan / ASan-on-C). A
`<defer_dynamic>` still requires `<dup_check>` (same site+class keying as a crash).

## Dispatch — where each DEFER lands

The DEFER reason is the join key into the two downstream tables. A row here maps
1:1 to a `capabilities.md` capability, which gates the fuzz rung, which
[`find-to-fuzz.md`](find-to-fuzz.md) resolves to a template + oracle:

| DEFER row | `capabilities.md` capability | fuzz rung (find-to-fuzz dispatch) |
|---|---|---|
| trait-trust, panic-safety, higher-order | `unsafe_trait_trust` | `adversarial_impl` + Miri |
| Send/Sync variance, generic-soundness | `unsafe_generic_soundness` | `sendsync_compileproof` (compiler) / adversarial |
| structure-gated repro | `untrusted_deserialization` + `structure_gated` sub-signal | grammar rung (`Arbitrary` AST + `-dict=`) |
| uninitialized read | `untrusted_deserialization` (908 sub-case) | `index_arbitrary` shape under **MSan** (`-Zbuild-std`) |
| C-FFI format string | `outbound_ffi` | `byte_parser` + ASan-on-C / `%n` oracle |

The capability's `present` value ([`capabilities.md`](capabilities.md) §Scope) is
the prior gate: if a class's capability is `present: no` (proven by grep, e.g.
russcan's `inbound_c_abi: no`), there is nothing to DEFER — the row is a logged,
evidenced skip, not a silent one. DEFER only fires when the capability is present
and static *reached but couldn't settle* the sink.

## Triage side — a DEFER is not an FP, and CLEAN-where-you-should-DEFER is the bug

The triage rules ([`fp-rules.txt`](fp-rules.txt)) close the loop so a correct
deferral is never mis-scored:

- **R9** — "we don't call that path" does not make a deferred soundness sink an
  FP; a public/exported API keeps it (downgrade reachability, keep the finding).
- **R10** — a deferred panic-safety sink is *memory* safety; do not re-close it
  with the availability-only R5 lens.
- **R11** — on a labeled corpus, a deferred sink that turns out real-but-unseeded
  is `real_latent` (a WIN), never an FP. The soundness bar R11 sets is literally
  "*or, for soundness classes, a **DEFER-TO-DYNAMIC-confirmable adversarial
  impl***" — i.e. the DEFER *is* the accepted proof form.

The inverse is the failure this page exists to prevent: **returning CLEAN on a row
the map says to DEFER is a false negative**, and (on a labeled corpus) it silently
depresses recall. Per [`fp-rules.txt` R11](fp-rules.txt), rust-mizan's measured
specificity of 84% counted four "false alarms" on *fixed* variants that were
actually real latent soundness bugs the seeded fix never touched — the same
soundness classes this page routes to DEFER; scored as `real_latent` rather than
FP, true precision was ~100%. Settling them dynamically is what surfaces that
truth instead of hiding it as a CLEAN.

## Auto-escalate to a fuzz harness (P1.1 / P1.2 — L11)

The find-ceiling rule above stops a finder from *returning CLEAN* on a DEFER row.
This rule stops the opposite failure the campaigns exposed (L11): a finder that
hand-crafts inputs for 90+ minutes and **never writes a fuzz harness**, even
where `cargo-fuzz`/Miri are installed. On x509 the finder crafted inputs for
93 min and produced no harness though `fuzzing.md`'s staircase prescribes one;
on lopdf, once a seeded fuzz *was* run, it rediscovered the real bug in ~2 min.

So the dynamic-fuzz stage is **first-class and always-run** for a target whose
`capabilities.run_crash_track()` is true (a byte-mutation surface — P0.4), seeded
from the corpus **and** the static findings (each DEFER/static candidate becomes
a seed via the reattack bridge), not gated behind a Track-A crash. And a finder
that has spent **N tool-calls without a candidate input** must stop hand-crafting
and emit a `cargo-fuzz` harness (the `fuzzing.md` staircase), built under the
*shipping* profile (`build_profile.py` / P0.1) so it doesn't manufacture
overflow-checks artifacts. "No crash yet" is a reason to write the harness, not
to keep guessing bytes. This is profile-general: the fuzz stage attaches to the
reattack bridge every profile already provides (`Profile.build_reattack`).

## See also

- [`find-to-fuzz.md`](find-to-fuzz.md) — the CWE/capability → template → oracle
  dispatch, and §5's "a no-crash is a capability map" (the fuzz-stage twin of this
  page's FIND-stage rule).
- [`capabilities.md`](capabilities.md) — the `present ∈ yes|no|test_only|partial`
  gate; a DEFER only fires for a *present* capability, and `structure_gated` is the
  sub-signal that jumps straight to the grammar rung.
- [`fuzzing.md`](fuzzing.md) — the rung menu (blind → FFI-ABI → coverage →
  rustc-native sancov) and the "fuzz the trait impl, not the bytes" axis that owns
  every DEFER-TO-DYNAMIC soundness row.
- [`fp-rules.txt`](fp-rules.txt) — R9/R10/R11: why a deferral is a finding, not a
  CLEAN, and why a `real_latent` DEFER is a WIN, not a precision hit.
- [`find_prompt.py`](../../harness/rust/find_prompt.py) — the finder's
  `<defer_dynamic>` Alternate-output block: the four `class:` values and
  `suggested_oracle:` menu this page's DEFER rows map onto.
