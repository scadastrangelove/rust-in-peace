# Capability-gated checks (android-app)

A target's *shape* decides which specialized checks are worth running. On a
decompiled APK the clearest case is native/JNI fuzzing: it only makes sense if a
bundled `.so` is actually reached by an attacker-controlled argument through a
Java→JNI chain — on an app that ships a `.so` nothing calls from an untrusted entry,
there is nothing to fuzz, and running it is wasted effort. The same is true of the
WebView bridge track (only if a JS bridge exists), the ContentProvider track (only
if a provider is exported / loosely permissioned), and so on.

So the methodology is **capability-gated**, not a flat checklist:

1. The `threat-model` skill inventories the app's capabilities into
   `THREAT_MODEL.md` §9 (`present` ∈ `yes|no|test_only|partial`, with evidence) and
   its machine twin `capabilities.json`.
2. Each stage — find, oracle, dynamic promotion, triage — enables the checks mapped
   to every capability whose `present` is **not `no`**, and skips the rest.

An absent capability is a *deliberate skip with a paper trail* (§9 says `no`, here's
the grep/manifest line that proved it), not an oversight. This file is the human
contract twin of the android rows in `harness/capabilities.py` `_GATES` — keep the
two in sync (the code is the authority; a stage routes off `_GATES`, not off this
table).

## Detecting each capability

| capability | signal (how §9 decides `present`) |
|---|---|
| `exported_ipc` | an Activity/Service/Receiver with `android:exported="true"` (or implicitly exported pre-API-31 via an `<intent-filter>`), addressable by another app |
| `webview_bridge` | a WebView with `setJavaScriptEnabled(true)` **and** `addJavascriptInterface(...)` and/or file access (`setAllowFileAccess`/`setAllowUniversalAccessFromFileURLs`) |
| `deeplink_applink` | an `<intent-filter>` with `<data android:scheme=…>` (custom scheme) or an `autoVerify` App Link host |
| `pending_intent` | a `PendingIntent` handed to another component/app that is `FLAG_MUTABLE` or built on an implicit base intent |
| `content_provider` | a `<provider>` `exported="true"`, or with a weak/normal `android:permission`, or with `grantUriPermissions`; SQL / `openFile` built from caller input |
| `insecure_storage` | a secret/token/PII written to SharedPreferences (esp. `MODE_WORLD_*`), SQLite, external/shared storage, or a log |
| `cleartext_tls` | `android:usesCleartextTraffic="true"`, a permissive `network_security_config`, `http://` endpoints carrying auth, a disabled `TrustManager` / no pinning |
| `dynamic_code_load` | `DexClassLoader`/`PathClassLoader`, `Class.forName`/`Method.invoke` on a dynamic name, `ObjectInputStream`/deserialization over untrusted bytes |
| `build_config_exposure` | manifest build-config: `android:debuggable`/`allowBackup`/`testOnly`, missing ProGuard/R8, no `full-backup-content` rules |
| `android_native_code` | a bundled `lib*.so` + native-method declarations (`System.loadLibrary` + `native`) — **gated by the reachability axis below** |

## Gating matrix — capability → scan §A → oracle → promotion → triage

The oracle for the app-security classes is a **reachability witness** (a static
entry→sink argument, strength 1), NOT a memory sanitizer — so `sanitizer` is `none`
for every row except `android_native_code`, which carries `asan` (JNI). The
"promotion" column is the witness-promotion path (the `fuzz_rung` in `_GATES`), not a
byte-mutation rung.

| capability | scan §A | oracle (detector) | promotion path → strength | triage AR |
|---|---|---|---|---|
| `exported_ipc` | §A1 IPC/exported | reachability witness → adb intent probe | `adb_intent_probe` — Tier A light_adb → **s2** | AR1, AR8 |
| `deeplink_applink` | §A2 Intent/PendingIntent/deeplinks | reachability witness → adb deeplink probe | `adb_deeplink_probe` — Tier A → **s2** | AR1, AR8 |
| `pending_intent` | §A2 Intent/PendingIntent/deeplinks | reachability witness (static) | `static_argument` — no promotion, stays **s1** | AR8 |
| `webview_bridge` | §A3 WebView/JS-bridge | reachability witness → Frida bridge hook | `frida_bridge_hook` — Tier B heavy_instrumented → **s3** | AR8 |
| `insecure_storage` | §A4 storage/data-leakage | storage observation (adb run-as) | `adb_storage_observe` — Tier A, domain=storage → **s2** | AR4, AR8 |
| `cleartext_tls` | §A5 TLS/cleartext/NSC | network observation (mitm) | `mitm_network_observe` — domain=network → **s2** adb-tcpdump / **s3** instrumented proxy | AR3, AR8 |
| `content_provider` | §A6 ContentProvider | reachability witness → adb provider probe | `adb_provider_probe` — Tier A → **s2** | AR5, AR8 |
| `dynamic_code_load` | §A7 dynamic-code/reflection/deser | reachability witness (static) | `static_argument` — no promotion, stays **s1** | AR7, AR8 |
| `build_config_exposure` | §A8 build-config | manifest static (terminal) | `static_terminal` — **s1**, terminal → `real_latent_static_argument` | AR2 |
| `android_native_code` | §A9 native/JNI reachability | ASan (JNI) — gated on native reachability | `jni_libfuzzer_asan` — native_crash → **s4** | AR9 |

Strength legend (see `harness/witness.py` `strength_of` and `default_disposition`):

- **s1** `static_reachability` — an argued path, not an artifact. Default disposition
  is `contested` (needs promotion) UNLESS the class is terminal (§A8) →
  `real_latent_static_argument`. This is the ADR-4 honesty gate (AR8): the agent
  cannot self-declare a finding terminal.
- **s2** `dynamic_observation / light_adb` — Tier A (ADR-5): `am start` / adb deeplink
  / provider probe / `run-as` read / logcat. Cheap; observed → `confirmed`.
- **s3** `dynamic_observation / heavy_instrumented` — Tier B (ADR-5): Frida + emulator,
  instrumented MITM. Observed → `confirmed`.
- **s4** `native_crash` — a reproduced JNI/.so ASan crash. `confirmed`.

Severity (`INFO..CRITICAL`) is ORTHOGONAL to strength: the honesty gate sorts on
strength, triage priority sorts on severity.

Absent (`present: no`) rows are simply not run — a logged, evidenced skip.
`test_only`/`partial` rows run but rank as latent hardening.

## Routing axis (not a capability) — `native_reachable_from_untrusted_input`

Emitted at the top level of `capabilities.json`, `present ∈ {yes, partial, no,
unknown}`. It is **not** a check to gate on/off but a **gate on the android-native
track** (ADR-1). A bundled `.so` alone is not a reason to fuzz JNI: the native
ASan/libFuzzer stage (`android_native_code` → §A9) runs only when
`native_reachable_from_untrusted_input ∈ {yes, partial}` — i.e. the chain
entry → Java → JNI → attacker-controlled argument is confirmed. `no`/`unknown` →
**skip the JNI fuzz**, a paper-trailed down-rank (AR9), not a silent omission.
Absence == `unknown`, NOT `no`: we only run the track on an explicit, evidenced
`yes`/`partial`. In code this is `CapabilityInventory.run_android_native()`
(= `android_native_code` active AND the axis ∈ {yes, partial}).

This is the android analog of the cpp/rust `reachable_from_public_api` axis (which
down-ranks an `unreachable-as-extracted` finding); android carries its own axis
because the native side track has a hard gate, not just a ranking nudge.

## Vote budget (union-of-N)

`vote_budget(capability)` routes how many find runs surface a class's tail:

- **Stable (N=3)** — the deterministic manifest/adb classes: `exported_ipc`,
  `deeplink_applink`, `pending_intent`, `content_provider`, `insecure_storage`,
  `cleartext_tls`, `build_config_exposure`. Single-run recall is already strong.
- **Default (N=5)** — the reasoning-heavy classes: `webview_bridge`,
  `dynamic_code_load`.
- **High-variance (N=8)** — `android_native_code`, which inherits the Rust JNI-fuzz
  tail. A target's budget is the MAX over its active capabilities.

## Scope

`threat-model` produces §9 **and** its machine twin `capabilities.json`.
`harness/capabilities.py` parses it and each stage gates programmatically — `find`
appends the mapped §A sections (`scan_sections()`), the dynamic stage picks the
promotion path (`gates_for(cap).fuzz_rung`) and the sanitizer for the native track
(`sanitizers()`), and every `present: no` row becomes a logged, evidenced skip. A
reviewer can read this table by hand, but the routing no longer depends on it: the
`_GATES` code path is the contract.
