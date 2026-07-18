# Extending the pipeline to a new technology

`docs/customizing.md` covers the mechanics of adding a profile (a
`harness/<lang>/` package + one `Profile(...)` entry in `harness/profiles.py`).
This doc is the *methodology* on top of it: the ordered gates a new-technology
port must clear, the one place where a hard target forces a change to the shared
core, and a worked application to Android (`android-app`).

It is written from the cpp → rust experience, generalized.

## The invariant — and where it stops holding

The rust port held to one invariant (see `profiles/rust/README.md`):

> the pipeline's shape is unchanged — an agent crafts an input, a detector
> fires, verifiers check, an analyst assesses exploitability. Only the swappable
> nouns change: **detector**, **bug taxonomy**, **crash signatures**.

That is true for any technology whose bugs terminate in an **executable crash**
(C/C++ → ASan; Rust → Miri/ASan/panic/hang). The generic orchestration
(`cli/find/grade/judge/report/dedup`, `scorecard`, union-of-N) never had to
change, because the artifact passed from `find` → `grade` → `judge` → `report`
was always the same thing: *a crashing input + a detector excerpt.*

Android breaks this. Most Android findings are **logic / configuration /
platform** bugs (exported components, IPC, WebView bridges, insecure storage,
cleartext, deeplink redirection) that have **no crash oracle**. Transferring the
Rust playbook here over-weights native/JNI fuzzing precisely because native is
the one Android surface that *does* crash — which is a small, side surface for a
real APK. The fix is not "find another ASan." It is to generalize the artifact.

## The central generalization: `CrashArtifact` → `SecurityWitness`

Replace the single artifact the pipeline carries with a typed **evidence** value:

```
SecurityWitness(kind, tier, repro, evidence)

kind ∈ { native_crash, dynamic_behavior, network_observation,
         storage_observation, static_reachability }
```

Rust and C become the special case `SecurityWitness(kind=native_crash)`. This
turns rust-in-peace from a *crash* pipeline into a *vulnerability-evidence*
pipeline — which is the actual differentiator the project needs: reasoning over
a real trust boundary, not one more native fuzzer.

Three properties make this honest rather than a rename:

1. **An explicit strength ordinal (1..4), and the scorecard weights by it.** A
   finding is reported by its *strongest* witness and labeled with that number.
   `static_reachability` (1) never gets reported as "verified."

   | strength | Witness | Meaning |
   |---|---|---|
   | **1** | `static_reachability` | a reachability *argument* only — a candidate, cheap to fabricate |
   | **2** | `dynamic_observation` / light (adb, am, logcat, run-as) | an effect observed cheaply |
   | **3** | `dynamic_observation` / heavy (Frida, emulator) | an effect observed under instrumentation |
   | **4** | `native_crash` | a reproducible crash (the cpp/rust special case) |

   Strength is **evidential rigor** (hard-to-fake / reproducible) — the right axis
   for the honesty gate. **Severity is a separate, orthogonal field** (impact): a
   strength-4 DoS panic can be LOW, a strength-3 token exfil CRITICAL — so the
   scorecard sorts honesty on strength and triage priority on severity, and a
   finding may carry several witnesses (confidence = `max(strength)`, report lists
   all). An all-strength-1 scorecard is a pile of candidates, and must say so.

2. **Each kind carries its own verification procedure**, which the adversarial
   grader runs to try to *disprove* the witness:
   - `native_crash` — re-run PoC bytes, detector fires (today's behavior).
   - `dynamic_behavior` — replay the adb/Frida PoC on a device, observe the effect.
   - `network_observation` / `storage_observation` — re-run the exercise, capture the wire / the file.
   - `static_reachability` — re-walk the cited call chain (entry → sink) and
     re-check the guard analysis. The grader adjudicates the *argument*.

3. **Backward-compat is a hard requirement, not a goal.** `native_crash` must
   reduce to exactly today's grade/dedup/scorecard behavior; the existing
   cpp/rust tests are the regression guard. This is an evolution of the shared
   harness contract — the first change that leaves "add-a-profile" territory —
   so it ships behind that guard, staged, with cpp/rust bit-identical before and
   after.

## The extension checklist (G0–G12)

Ordered gates. **G2 is make-or-break**; a weak witness set degrades everything
below it.

- **G0 — Unit of analysis + untrusted-input boundary.** One sentence: "untrusted
  X reaches Y, we hunt Z." *Hard when* there are several input classes (APK: 5+).
- **G1 — Bug taxonomy.** 5–10 risk classes, each with its trust boundary. *Hard
  when* no standard exists (Android has one: MASVS/MASTG).
- **G2 — Witnesses.** For each G1 class, which `SecurityWitness` kind proves it,
  at which tier. *Hard when* bugs are logical/config (no crash) → mostly ARGUED,
  wanting dynamic promotion.
- **G3 — Target contract.** Driver/harness + container + `config.yaml`
  (`profile:`, `reattack_harness:`, capabilities). *Hard when* it needs a
  device/emulator, not a compiler (breaks the gVisor isolation model — see below).
- **G4 — Finding identity + witness attach.** The dedup key is the *finding*
  (entry → sink), not the witness; witnesses attach and upgrade it.
- **G5 — Capabilities schema (§9 machine form).** Attack-surface inventory →
  routing. For Android this file is *also a finder input*, not only a router.
- **G6 — Witness producers + promotion.** For executable-crash tech: fuzz
  templates + the find→fuzz `reattack` bridge. For evidence tech: the
  **promotion** stage `find → generate PoC → replay → observe → upgrade tier`.
- **G7 — Recall discipline.** union-of-N, vote budget, DEFER-TO-DYNAMIC.
- **G8 — FP precedents (R-rules) + scan-extras.** The domain's characteristic
  false positives + reverse-calibration.
- **G9 — Scorecard / honesty gate.** DISPOSITION schema, "0 findings needs a
  reason," and now **tier labeling** so ARGUED ≠ OBSERVED.
- **G10 — Validation targets.** canary (planted + decoy), real-world, labeled
  benchmark.
- **G11 — Interactive skills.** threat-model §9, vuln-scan `--extra`, triage
  `--fp-rules`, customize. Value without Docker/device.
- **G12 — Iterate.** transcript review; several pipeline variants → union.

## Tool layering: wrap, don't reimplement

rust-in-peace wraps Miri/ASan/cargo-fuzz — it does not reimplement them. Same
discipline for a new tech: place existing tools by layer, keep the pipeline's
value in reasoning / verification / recall / honesty.

| Layer | Role | Gate | Android tools |
|---|---|---|---|
| **L1 — unpack/decompile** | target prep (deterministic) | G3 | apktool, jadx, baksmali, dex2jar+CFR, apksigner, unzip (→`.so`/assets/certs) |
| **L2 — surface/metadata** | feeds `capabilities.json` §9 | G5 | androguard, apkanalyzer/aapt2, APKiD (packer/obfuscator) |
| **L3 — rule-based scanners** | **recall seeds / candidate generators — NOT verdicts** | G6/G7 | MobSF (REST/JSON), QARK, semgrep (mobile rules over jadx), FlowDroid/Amandroid (taint) |
| **L4 — dynamic** | witness promotion → OBSERVED | G2/G3 | Frida, objection, drozer (IPC), adb `am start`, emulator/AVD/Corellium |
| **L5 — native fuzzing** | capability-gated escalation | G2/G6 | extract `.so` → NDK + libFuzzer/AFL++ + ASan on JNI exports (= the existing cpp profile) |

**The discipline that keeps this from becoming "one more MobSF":** L3 scanners
are pattern-matchers with high FP and a hard recall ceiling. Their output is an
*input to grade+triage*, never a verdict. The differentiated value the pipeline
adds — that L1–L3 do not — is (1) reachability adjudication, (2) adversarial
verification with a PoC, (3) recall via union-of-N over several scanners + agent
passes as independent finders, (4) calibrated FP triage + honest tier-labeled
scorecard.

## Worked application: the `android-app` profile

Core is **application security over DEX**, reasoning about Android framework
semantics regardless of whether the source was Java, Kotlin, or generated. From
a shipped APK there is no Kotlin source — only DEX bytecode, jadx's Java-ish
decompile, smali (the faithful representation), the manifest, and resources.

```
Manifest/resources → DEX/jadx/smali → Android entry-point graph
→ attacker-controlled input → guard/permission/validation
→ security-sensitive effect
```

**Entry points:** Activity · Service · BroadcastReceiver · ContentProvider ·
deep link / App Link · PendingIntent · WebView navigation/bridge · file/content
URI · Binder interface · notification action · imported document / external
storage.

**Sinks:** sensitive-data return · privileged operation · authenticated API call
· file/DB access · intent forwarding · WebView native method · token/credential
exposure · arbitrary URI/file access · query construction · dynamic code loading.

This — not memory safety — is the bulk of the taxonomy, prompts, capabilities,
canary, and scorecard (MASVS/MASTG: IPC & exported components, Intent/PendingIntent/
deeplinks, WebView & JS bridges, insecure storage & data leakage, TLS/cleartext/
Network Security Config, auth/session, biometrics & Keystore, screenshots/
clipboard/notifications, dynamic loading/reflection/serialization, privacy flows).

### Native is a capability-gated router, not a co-equal world

A bundled `.so` (image codec, SQLite, crypto, analytics SDK, RN/Flutter runtime,
game engine, integrity helper) says nothing on its own. T2 (native fuzzing) fires
**only** when a chain is confirmed:

```
Android entry point → Java/Kotlin processing → JNI call
→ attacker-controlled argument → native parser/sink
```

Expressed in capabilities so routing is automatic:

```json
{
  "android_native_code": { "present": "yes", "evidence": "lib/arm64-v8a/libfoo.so" },
  "android_native_reachable_from_untrusted_input": {
    "present": "partial",
    "evidence": "Java_com_app_Parser_parse receives attacker-controlled byte[]"
  }
}
```

Without the reachability chain, exported JNI symbols are mostly uncallable
outside ART or off the security boundary — time sink, not signal.

### Staging + effort (engineering heuristic, not a market statistic)

1. **`android-app-static`** — Manifest + DEX reachability witnesses (ARGUED). No
   device. Clears G0–G5, G8, G9, G11.
2. **`android-app-dynamic`** — adb/instrumentation/Frida promotion of static
   candidates to OBSERVED. Needs the device-sandbox design.
3. **`android-native`** — only for confirmed JNI/native paths (capability-gated).
4. Unified dedup + scorecard across all three.

| Direction | Effort |
|---|---|
| Manifest + DEX reachability + Java/Kotlin/framework taxonomy | 55–65% |
| Dynamic adb/instrumentation verification | 20–30% |
| Capabilities, FP rules, scorecard, benchmarks | 10–15% |
| Native/JNI routing | 5–10% |

### G8 / G10 specifics

- **FP precedents (Android is FP-heavy):** exported but guarded by a signature/
  `protectionLevel` permission → not live; `debuggable` in a debug build;
  cleartext to localhost; a "hardcoded secret" that is a public key; a provider
  with scoped `grantUriPermissions`. Strong reverse-calibration, like rust's
  R8–R11.
- **Benchmarks:** DIVA, InsecureBankv2, AndroGoat, DVHMA, Pivaa, OWASP MASTG
  Hacking Playground.
- **Canary decoy archetype:** an exported component that *looks* vulnerable but
  is protected by a signature permission (unreachable) — the Android analog of a
  `defect:false` decoy.

## Open design decisions

Flagged, not yet resolved:

- **Witness contract location.** Does `SecurityWitness` live in the shared core
  (touches grade/judge/dedup/report/scorecard, behind the cpp/rust regression
  guard) — or do we keep the core `native_crash`-only and have the android
  profile fake a witness locally? The former is the "universal evidence
  pipeline"; the latter is cheaper but leaves the scorecard's tier-honesty
  profile-local. Recommendation: shared core, staged behind backward-compat.
- **Dynamic sandbox.** Emulator/Frida needs KVM/device — a different isolation
  model than the gVisor egress-restricted container. Design the device sandbox
  (pool, snapshot/restore between PoCs, network capture) before committing to
  `android-app-dynamic`.
- **Decompile fidelity.** jadx-Java is lossy; smali is faithful but verbose;
  obfuscation (R8/packers, detected by APKiD) degrades both. Reachability
  witnesses should cite smali line refs, cross-checked against jadx for
  readability.
