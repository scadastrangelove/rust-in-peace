# Android Profile — Architecture Decisions (ADR)

Merge of the initial decomposition (native-crash-first) and the review that moved
the focus to the Java/Kotlin/framework surface, plus refinements that remove
concrete implementation risks. This record fixes **how the agent reasons over the
artifact**; the standards / MASVS taxonomy / tooling / FP catalogue / benchmarks
live in the profile's reference material (`profiles/android-app/`) and are not
superseded here.

Generalizable methodology (any technology, not just Android) lives in
[`docs/extending.md`](../../extending.md); this file is the Android-specific
record. Each decision notes **where it is realized in code**.

Track names: `android-app-static` (Tier-A adb confirmation included) ·
`android-app-dynamic` (Tier-B, heavy) · `android-native` (capability-gated
escalation).

---

## ADR-1 — Managed code (Java/Kotlin/framework) is the primary surface; native is a capability-gated side track

**Decision.** The MVP is built around Manifest + DEX + framework reasoning;
native/JNI fuzzing is a secondary track, activated only on a proven reachability
chain.

**Why.** Ranking native as "the cleanest execution-verified slice, almost free"
is an argument about *build convenience*, not about where value sits. The deeper
reason native is the only execution-verified track is **toolchain asymmetry**:
the Rust profile is strong because there is a compiler in the loop (rebuild with
Miri/ASan instrumentation). A shipped APK's managed layer has **no such path** —
decompiled Java/smali is a terminal artifact, not a recompilable input. Native is
the one Android surface that preserves the build-with-instrumentation path
(extract `.so` → NDK rebuild → ASan/libFuzzer). So native stays execution-verified
as a *consequence of toolchain capability*, not as evidence that the bugs live
there.

**Practical consequence.** `android-native` activates only when a capability check
proves the chain **Android entry point → Java/Kotlin processing → JNI call →
attacker-controlled argument → native sink** — not merely `native_libs[] ≠ ∅`.

**Realized in code.** `harness/capabilities.py`: the `native_reachable_from_untrusted_input`
routing axis + `CapabilityInventory.run_android_native()` (active `android_native_code`
AND chain ∈ {yes,partial}); a bare `.so` returns `False`.

---

## ADR-2 — The profile is `android-app` (substrate: DEX/smali/manifest), not `android-kotlin`

**Decision.** The name reflects the analysis substrate, not the source language.

**Why.** A shipped APK has almost no Kotlin source — DEX bytecode, jadx
decompile, smali, manifest/resources. The profile reasons about Android framework
semantics over DEX regardless of whether the source was Java, Kotlin, Scala, or
generated (Compose, KSP). After decompilation the Java/Kotlin distinction is gone
(both → JVM bytecode → DEX/smali), so the decision does not depend on any "% of
apps that use Kotlin" figure — the load-bearing premise is only that the managed,
framework-facing surface is far larger than the native one (ADR-1).

This is also the structural asymmetry with Rust worth stating outright: the Rust
profile works on trusted, **recompilable source**; the android-app profile works
on a decompiled, **non-recompilable artifact** with no compiler in the loop. That
is the real reason G2/the oracle differs — the whole toolchain contract differs,
not just the bug class.

**Realized in code.** Profile id `android-app` in `harness/profiles.py`; package
`harness/android_app/`.

---

## ADR-3 — Primary structure is the entry→sink graph; MASVS/MASWE is metadata on the found path

**Decision.** The find/reachability reasoning walks the artifact as a graph of
sources and sinks; the MASVS category / MASWE id is attached to a found path as
report/dedup metadata, and does not drive traversal order.

**Why.** MASVS categories organize a human checklist and label a finding for the
report ("this is a STORAGE finding"); they do not tell the agent *how* to search.
Reachability source→sink does. Category is the right layer for the reference
baseline (what to check) and for report/scorecard (what to call it); the graph is
the right layer for the search mechanics.

**Caveat (accepted refinement).** A pure graph is combinatorial (exported × sinks).
It is bounded by the existing `recon` (partitions entry points into focus areas) +
capabilities pruning: androguard enumerates entry points deterministically → recon
partitions → capabilities prune unreachable → the agent runs source→sink per
partition. Without that bound the find agent drowns.

**Realized in code.** `harness/android_app/find_prompt.py` (graph-first hunt, class
as label); `harness/android_app/detect.py` (dedup signature = (finding_class, sink
site)).

---

## ADR-4 — `SecurityWitness` replaces the crash-only artifact, with an explicit strength ranking

**Decision.** The evidence a finding carries is a typed `SecurityWitness` with an
explicit `strength` (1..4) consumed by the scorecard / DISPOSITION gate:

    1  static_reachability            — an argument, not an artifact
    2  dynamic_observation/light_adb  — observed via adb/am/logcat/run-as
    3  dynamic_observation/heavy_instrumented — observed via Frida/emulator
    4  native_crash                   — a reproducible crash (Rust/C special case)

`strength` is **evidential rigor** (how hard to fabricate / how reproducible) —
the right axis for the honesty gate. **`severity` is a separate, orthogonal
field** (impact): a strength-4 native DoS-panic can be LOW; a strength-3 token
exfil can be CRITICAL. Sorting the scorecard by strength alone would rank the
DoS above the exfil — wrong. So strength gates honesty (contested vs confirmed),
severity gates triage priority; the report shows both. A finding may carry
several witnesses; its confidence is `max(strength)` and the report lists all.

**Why ranking, not a bare enum.** A crash is hard to fake; a `static_reachability`
witness is an *argument*, cheap to fabricate. Without explicit strength feeding
the DISPOSITION gate, the "recall-first under a hard correctness gate" discipline
silently erodes on weak-oracle Android classes.

**DISPOSITION rule (with anti-gaming).** A strength-1 finding defaults to
`contested` (needs promotion to strength ≥ 2), **except** when its class is in a
**declared** static-terminal set — pure build-config checks with nothing stronger
to observe (missing ProGuard, allowBackup, debuggable, cleartext-config,
exported-without-permission-as-config, backup-no-rules, testOnly). Only those may
be `real_latent_static_argument` (separately tagged, never silently merged with
observed findings). Static-terminal is a property of the **class id**, NOT a
per-finding agent judgment — an agent cannot self-declare a weak reachability
finding terminal to skip promotion.

**Realization decision (backward-compat is a hard requirement).** The conceptual
`CrashArtifact → SecurityWitness` generalization is realized **additively**, not
as a disruptive core rename: the witness is carried *inside* the existing
`CrashArtifact` — `crash_type` is the finding class, and `crash_output` begins
with a machine-parseable `WITNESS:` header the detector reads back. `native_crash`
writes no header (absence ⇒ strength 4), so cpp/rust artifacts, grade, dedup, and
scorecard are **bit-identical** before and after. The union-of-N layer's existing
`is_confirmed` (passed grade / ≥2 votes) and `is_contested` (found statically,
not settled → dynamic-confirm queue) already encode observed-vs-argued; strength
makes it explicit and tier-labeled. (A full core rename remains a future option if
we want witness typing in the shared dataclasses; not needed for the MVP.)

**Realized in code.** `harness/witness.py` (kinds, `strength_of`, `SEVERITIES`,
`STATIC_TERMINAL_CLASSES`, `default_disposition`, the `WITNESS:` header parse);
`harness/android_app/detect.py` reads it; cpp/rust unaffected (headerless ⇒ 4).

---

## ADR-5 — Dynamic verification is two cost tiers, not one budget line

**Decision.** Split "adb/instrumentation verification" into:

* **Tier A — light / adb-only**: `adb backup` extraction, `am start`/`am broadcast`
  with a crafted Intent, `logcat`, `run-as` file inspection. No Frida, no full AVD
  harness. Ships alongside `android-app-static`. → `dynamic_observation/light_adb`,
  strength 2.
* **Tier B — heavy / instrumented**: Frida hooking, full emulator/AVD in a
  container, multi-step auth-flow probing, MASVS-RESILIENCE bypass. A separate
  engineering project — this is `android-app-dynamic` proper. →
  `dynamic_observation/heavy_instrumented`, strength 3.

**Why.** Storage tests need to actually check whether a created file holds
sensitive data (MASTG-TEST-0200) — Tier A answers that; detecting the API call
statically does not. Treating "dynamic" as one 20–30% line hides two components
with very different schedule risk.

**Accepted refinement — the sandbox boundary.** Tier A is *not* free: `adb`/`am`/
`run-as` need a running Android instance (a light, headless, snapshot-boot
emulator; no Frida). So **pure static = the true zero-infra first milestone**
(device-free, ships first), and **Tier A = the first increment that stands up the
light device sandbox**. This keeps "static-first defers the sandbox problem"
honest and gives a crisp milestone boundary. (The gVisor egress-restricted
container of `docs/security.md` does not host an emulator — the device sandbox is
its own design: pool, snapshot/restore between PoCs, network capture.)

**Realized in code.** `harness/witness.py` tiers; `harness/android_app/find_to_fuzz.py`
(`build_reattack` = the promotion dispatch: capability → Tier-A/B PoC plan);
`harness/capabilities.py` `fuzz_rung` per capability (adb_intent_probe,
adb_storage_observe, frida_bridge_hook, …).

---

## ADR-6 — Effort split is an adaptive per-target prior, not a fixed global budget

**Decision.** Baseline heuristic: ~55–65% Manifest+DEX+reachability taxonomy ·
~20–30% dynamic verification (split by ADR-5) · ~10–15% capabilities/FP/scorecard/
benchmarks · ~5–10% native/JNI routing — as a prior for a *median* APK, not a
fixed budget. The `native_reachable_from_untrusted_input` gate + the reachability
chain reweight per target: a thin-UI-over-heavy-native-parser app (media/document,
proprietary codec, DRM) sharply raises the `android-native` share once the chain
is confirmed; a typical CRUD/business app stays near baseline.

**Realized in code.** `harness/capabilities.py` `vote_budget` (native = high-variance
tail) + `run_android_native()`; the router reweights recon/vote allocation from the
capabilities file.

---

## ADR-7 — The walk emits intelligence (`intel.json`), not only findings

**Decision.** The android-app walk emits a first-class **intelligence** artifact —
`intel.json` — alongside its vulnerability findings: the app's server endpoints /
hosts, bundled SDKs, requested permissions, deep-link schemes, exported-component
surface, and secrets *observed*. It is distinct from a finding (a finding is a
vulnerability witness; intel is data about the target).

**Why.** A C parser has no "endpoints"; an app does. The reachability walk already
enumerates the manifest + smali, so the same pass cheaply yields high-value
inventory. Most importantly, the **endpoints / hosts** list is the discovery
vector for **server-side** testing: the mobile client enumerates the API hosts a
downstream EASM / DAST / passive-DNS pipeline then attacks. The app is a discovery
vector for the server surface. `capabilities.json` (§9) is a partial precursor
(the exported-surface inventory); `intel.json` is its richer sibling.

Conceptually this widens the pipeline's output model: it emits both *witnesses of
vulnerabilities* and *intelligence about the target* — the crash→witness
generalization (ADR-4) has a sibling, the finding→intel generalization.

**Security.** Secrets are recorded by **kind + location only** (`redacted: true`);
the value is never stored, so `intel.json` is safe to hand to the server-side
pipeline.

**Realized in code.** `harness/android_app/intel.py` (`TargetIntel` +
deterministic `harvest(app_root)`, XML-namespace host denylist); the canary ships
an `intel` driver + fixture data (an API client, an OkHttp SDK marker, a fake
maps key) with `tests/test_android_intel.py` green. A real target's recon step
runs the same `harvest()` over apktool/jadx output.

---

## Where the strategic value sits (corollary)

The static-terminal set (ADR-4) is exactly what existing scanners (MobSF, QARK…)
already do with low FP — so `real_latent_static_argument` findings are the
*low-differentiation* ones. The project's unique value is the classes that **must**
be promoted to strength ≥ 2 (IPC / reachability / WebView / deeplink). That means
dynamic verification (Tier A especially) is not polish — it is where the
differentiator lives, reinforcing ADR-5's ranking of dynamic as second, not third.
