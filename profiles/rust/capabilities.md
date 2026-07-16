# Capability-gated checks

A target's *shape* decides which specialized checks are worth running. FFI-ABI
fuzzing is the clearest case: it only makes sense if the target exposes an
**inbound C ABI** that C code calls — on a pure-Rust library there is no such
boundary, the type system already rules out the length/pointer/lifecycle bugs it
hunts, and running it is wasted effort borrowed from a different target's threat
model. The same is true of TSan (only if there's concurrency), structured
deserialization fuzzing (only if untrusted structured input is parsed), and so
on.

So the methodology is **capability-gated**, not a flat checklist:

1. The `threat-model` skill inventories the code's capabilities into
   `THREAT_MODEL.md` §9 (`present` ∈ `yes|no|test_only|partial`, with evidence).
2. Each stage — find, detector, fuzzing, triage — enables the checks mapped to
   every capability whose `present` is **not `no`**, and skips the rest.

An absent capability is a *deliberate skip with a paper trail* (§9 says `no`,
here's the grep that proved it), not an oversight — which is exactly what stops
one target's needs (e.g. an in-process C ABI) from leaking in as a universal
step.

## Detecting each capability

| capability | signal (how §9 decides `present`) |
|---|---|
| `inbound_c_abi` | `#[no_mangle] pub extern "C"` / `pub extern "C" fn` reachable from the crate's public surface (C calls **into** Rust) |
| `outbound_ffi` | `extern "C" { … }` blocks / `*-sys` deps / `#[link]` (Rust calls **into** C) |
| `concurrency_async` | `tokio`/`async-std`/`rayon` deps, `thread::spawn`, `unsafe impl Send/Sync`, `Mutex`/atomics across `.await` |
| `untrusted_deserialization` | a parser/decoder over attacker-supplied structured bytes: `serde`/`bincode`/`prost`, or a hand-rolled length/offset/tag reader |
| `multi_tenant_authz` | a permission/ownership check on a shared resource; request carries a tenant/user identity |
| `unsafe_simd` | non-trivial `unsafe` density; `core::arch` intrinsics / `#[target_feature]` |
| `unsafe_trait_trust` | unsafe code that trusts a caller's trait impl — `size_hint`/`len`/`Ord`/`Borrow` feeding a length/ptr computation, or `ptr::read`/`set_len` around a user `Clone`/`Drop`/`next` (Rudra: higher-order-invariant + panic-safety) |
| `unsafe_generic_soundness` | `unsafe impl Send`/`Sync` for a generic type with no `T: Send`/`T: Sync` bound (Rudra: Send/Sync variance) |
| `network_protocol_parser` | parses a wire protocol (HTTP, DNS, TLS records…), esp. if a second implementation parses the same bytes |
| `subprocess_exec` | `Command`, `sh -c`, path/archive handling of attacker-influenced names |
| `crypto_secrets` | holds keys/tokens/MACs; comparisons, RNG choice, `Debug`/log exposure |

## Gating matrix — capability → specialized checks per stage

| capability | find (brief add-on) | detector | fuzzing rung | triage |
|---|---|---|---|---|
| `inbound_c_abi` | `scan-extras` §7 FFI emphasis | guard-page + ASan | **Stage 2 (FFI-ABI)** — [`fuzzing.md`](fuzzing.md) | panic-across-FFI is UB, not just abort |
| `outbound_ffi` | catch_unwind at boundary, allocator asymmetry, `from_raw_parts` on C ptr/len | ASan | — | R2: test-only vs shipped |
| `concurrency_async` | `scan-extras` §8 | **TSan / loom** | cancellation / loom model-check | `Send`/`Sync` soundness (R8/R9) |
| `untrusted_deserialization` | integrity ≠ bounds; eager alloc before validation | ASan + hang-timeout | **Stage 1 + Stage 3 mandatory**; `Arbitrary`/structured corpus seeded from real artifacts | R1 (invariant dominates the unsafe read); R7 (len→index) |
| `multi_tenant_authz` | `scan-extras` §6 authz-at-side-effect | — | — | R2 attacker- vs operator-reachable is the severity driver |
| `unsafe_simd` | `scan-extras` §2 unsafe audit (alignment/validity/aliasing) | **Miri** prioritized | libFuzzer over the unsafe entry point | R1 / R9 (soundness even if no caller today) |
| `unsafe_trait_trust` | Rudra higher-order / panic-safety brief | **Miri** (UB oracle) | **adversarial trait-impl fuzz** — lying `size_hint`/panicking `Clone`, [`fuzzing.md`](fuzzing.md) | R8 / R10 (panic-safety is memory-safety in unsafe code) |
| `unsafe_generic_soundness` | `scan-extras` §8 Send/Sync | Miri (multi-thread driver) | adversarial: cross-thread send of a `!Send` `T` | R8 / R9 (unsound `Send`/`Sync` is real even with no caller) |
| `network_protocol_parser` | `scan-extras` §9 parser differentials | — | **differential fuzz** vs the reference impl | parse divergence = a bug class itself |
| `subprocess_exec` | `scan-extras` §5 command/path/archive | ASan | path/zip-slip corpus | injection / traversal |
| `crypto_secrets` | `scan-extras` §10 secrets/crypto | — | — | constant-time; leak into Debug/logs |

Absent (`present: no`) rows are simply not run. `test_only`/`partial` rows are
run but ranked as latent hardening (they don't reach the shipped surface) — the
same distinction `fp-rules.txt` R2 draws.

The **fuzzing** column resolves to a concrete harness via
[`find-to-fuzz.md`](find-to-fuzz.md): CWE/capability → template
([`harness-templates/`](harness-templates/)) → agent-bound → compile+smoke
validated. That's how a graded finding becomes a reproduction.

## Worked example — russcan

Its §9 inventory and what it gates:

| capability | present | evidence | gates |
|---|---|---|---|
| `untrusted_deserialization` | **yes** | serialized-DB parser (`Database::load`) | Stage 1 + Stage 3 fuzz ✓ (done: 3M blind + 36.6M cargo-fuzz); integrity≠bounds find brief |
| `unsafe_simd` | **yes** | `russcan-simd` (121 unsafe), `core::arch` | Miri priority; §2 unsafe audit |
| `outbound_ffi` | `test_only` | `oracle` → libhs, not in the data plane | boundary hardening ranked latent (catch_unwind added) |
| `inbound_c_abi` | **no** | grep `extern "C"`/`#[no_mangle]` in the russcan crates = empty | **Stage 2 skipped** — no C ABI to fuzz |
| `concurrency_async` | no | no tokio/threads; block-mode, single-threaded scan | no TSan |
| `multi_tenant_authz` | no | DB is operator-compiled, trusted-by-construction | crafted-DB findings ranked latent (R2) |

So russcan's clean two-pass fuzzing (Stage 1 + Stage 3) wasn't an arbitrary
choice — it's what its capability set gates. **Stage 2 is a deliberate,
evidenced skip**, and it flips on automatically the day russcan ships its
libhs-compatible C ABI (`inbound_c_abi: no → yes`): that shim is new hand-written
unsafe pointer/length/lifecycle code the Rust-entry-point fuzzers don't cover.

## Ranking axis (not a capability) — `reachable_from_public_api`

Emitted at the top level of `capabilities.json`, `present ∈ {yes, no}`. It is not
a check to gate on/off but a **ranking** signal: is the finding's sink actually
driven by a public/exported entry on attacker-controlled input? A `no` expresses
the `unreachable-as-extracted` case the capability keys cannot — real code with
no public path to reach it (a function lifted out of its crate, an internal-only
helper). It **down-ranks a finding before fuzz time is spent** (rust-mizan
0013/0018/0028/0040 were all real-but-unreachable-as-extracted); absence ==
`unknown`, so we only down-rank on an explicit, evidenced `no`.

## `structure_gated` sub-signal

When `untrusted_deserialization` is `yes` **and** the format is a
magic/length/frame container a random byte stream almost never satisfies (0040's
ID3/synchsafe case), tag it `structure_gated` in the evidence. The dispatcher
uses this to jump straight to the grammar rung (`#[derive(Arbitrary)]` AST +
`-dict=`) after a blind pass fails, instead of burning the whole budget on raw
bytes — see [`find-to-fuzz.md`](find-to-fuzz.md) and the `grammar_parser.rs`
template.

## Scope

`threat-model` produces §9 **and** its machine twin `capabilities.json`.
`harness/capabilities.py` parses it and each stage gates programmatically —
`find` appends the mapped `scan-extras` sections, the `reattack` stage picks the
sanitizer (`gates_for(cap).sanitizer`) and fuzzing rung, and every `present: no`
row becomes a logged, evidenced skip. A reviewer can still read the table by
hand, but the routing no longer depends on it: the code path is the contract.
