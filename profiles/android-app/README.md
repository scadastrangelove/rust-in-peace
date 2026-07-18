# Android app-security profile

An **application-security** variant of this pipeline, added **alongside** the C/C++
+ ASAN default and the Rust fork (nothing in the base pipeline is modified). Its
target is a **decompiled APK**, not source: `AndroidManifest.xml` (decoded), `smali/`
(the faithful bytecode — the thing you cite for line refs), a jadx Java-ish decompile
(readable but lossy), and `resources/`. There is no recompilable source and no
compiler in the loop — you reason over the artifact, you do not rebuild it.

The bugs that matter here are **not** memory-safety: they are logic / IPC /
configuration / platform issues in the app's own Dalvik code and manifest — exported
IPC, WebView bridges, deeplink redirection, insecure storage, cleartext, content-
provider SQLi, dynamic code load. Most of that surface has **no crash oracle**, which
is why this profile generalizes the pipeline's evidence from a *crash* to a
**SecurityWitness** (`harness/witness.py`).

## The witness model — evidence carries a *strength*

The base pipeline had one kind of evidence: a crash (PoC bytes + a sanitizer trace,
hard to fake — it reproduces or it doesn't). That does not exist for an exported-
component or WebView-bridge bug over decompiled DEX. So a finding here carries a
typed **witness** with an explicit **strength** (1..4) — an ordinal of *evidential
rigor* (how hard the witness is to fabricate / how reproducible it is) that the
scorecard and the triage DISPOSITION gate consume. **Severity** (impact) is
**orthogonal** to strength: the honesty gate sorts on strength, triage priority sorts
on severity (a reachable token exfil is HIGH at strength 1; a native DoS can be LOW at
strength 4).

The primary oracle is a **reachability witness** (`kind=static_reachability`,
strength 1) — an attacker-controlled Android entry point reaching a security-
sensitive sink past insufficient guards, argued over the manifest and smali — **not a
crash**. strength ≥ 2 means an *observed* dynamic effect; a native ASan crash is
strength 4.

| witness kind | catches | strength | how it is obtained |
|---|---|---|---|
| `static_reachability` | an argued `entry → (hops) → sink` path over manifest/smali | **1** | the reachability oracle re-walks the candidate; **3/3 identical** re-runs = the android analog of the 3/3 crash bar |
| `dynamic_observation` / `light_adb` (Tier A) | an observed effect via adb/am/logcat/run-as | **2** | `am start` / adb deeplink / provider probe / `run-as` storage read / logcat |
| `dynamic_observation` / `heavy_instrumented` (Tier B) | an observed effect via Frida + emulator | **3** | Frida bridge hook, instrumented MITM |
| `native_crash` | a reproduced JNI/`.so` memory bug | **4** | ASan under a JNI libFuzzer harness (gated on native reachability) |

`native_crash` is the degenerate case the cpp/rust profiles produce implicitly (no
WITNESS header ⇒ strength 4), so the base profiles are untouched — a witness rides
*inside* the existing `CrashArtifact` (`crash_type` = the finding class,
`crash_output` begins with a machine-parseable `WITNESS:` header `detect.py` reads
back).

## Reachability is the oracle (ADR-3)

The organizing principle is a **reachability graph**, not a checklist. The agent
enumerates attacker-controlled **entry points** (exported Activity/Service/Receiver,
ContentProvider, deep link, PendingIntent, WebView + JS bridge, imported file/URI),
traces control/data flow to a security-sensitive **sink**, and decides whether a
**guard** (permission, `protectionLevel`, signature check, input validation,
`exported=false`, host allowlist) actually stops it. A finding is a concrete path
with the guard analysis explicit. The MASVS/MASTG category (PLATFORM, STORAGE,
NETWORK, CODE…) is **metadata** attached to the found path for the report — it never
drives the traversal order.

## Two-tier dynamic promotion (ADR-4 / ADR-5)

A `static_reachability` witness is an *argument*, cheap to fabricate. **ADR-4
anti-gaming**: a strength-1 finding defaults to **`contested`** (it wants dynamic
promotion) UNLESS its class is in `witness.STATIC_TERMINAL_CLASSES` — the closed set
of pure build/config properties with nothing further to observe (`android:missing-
proguard`, `android:debuggable-flag`, `android:allow-backup`, `android:cleartext-
config`, `android:exported-no-permission`, `android:backup-no-rules`,
`android:test-only-flag`) — in which case it is **`real_latent_static_argument`**,
separately tagged. The terminal set is keyed on the class **id**, not a per-finding
agent judgment, so an agent cannot self-declare a weak reachability finding terminal
to skip promotion.

Promotion has **two cost tiers** (ADR-5):

- **Tier A — light** (`light_adb`, strength 2): adb backup / `am start` / logcat /
  `run-as`. Cheap, no instrumentation.
- **Tier B — heavy** (`heavy_instrumented`, strength 3): Frida + emulator,
  instrumented MITM.

An observed effect at either tier moves the finding to **`confirmed`**. An all-static
run is therefore a pile of *candidates*, and the scorecard must say so rather than
reporting them as verified — the honesty requirement ADR-4 exists for.

The promotion engine (`harness/android_app/promote.py`) is a deterministic function
of `(witness, dispatch, observation)` gated on a **3/3** observed effect, so the
whole path is testable without a live emulator. The observation comes from driving
the app in the **device sandbox** ([`docs/profiles/android/DEVICE-SANDBOX.md`](../../docs/profiles/android/DEVICE-SANDBOX.md),
ADR-8) using the PoC skeletons in [`dynamic-templates/`](dynamic-templates/) (adb
Tier-A, Frida Tier-B). The `android-canary` `run_dynamic` replays recorded
observations through the engine as the CI proof.

## Native is a capability-gated side track (ADR-1)

android-native (JNI ASan fuzzing) is **not** part of the main app-security path. It
runs **only** when the routing axis `native_reachable_from_untrusted_input ∈
{yes, partial}` — i.e. a confirmed chain `entry → Java → JNI → attacker-controlled
argument`. A bare bundled `.so` is **not enough**: with no reachability chain the
finding is down-ranked (AR9), the JNI fuzz track stays off, and that skip carries a
paper trail. When the chain holds, a reproduced crash promotes to `native_crash`
(strength 4).

## Intelligence artifact — `intel.json` (ADR-7)

The walk emits more than findings. Alongside the vulnerability witnesses it
produces `intel.json` — a first-class **inventory** of the app's outward shape:
server **endpoints / hosts** it talks to, bundled **SDKs**, requested
**permissions**, **deep-link** schemes, the **exported-component surface**, and
**secrets observed** (recorded by kind + location only — `redacted: true`, the
value is never stored). A finding is a vulnerability; intel is data about the
target.

The endpoints/hosts list is the payload that bridges to **server-side testing**:
the mobile client enumerates the API hosts a downstream EASM / DAST / passive-DNS
pipeline then attacks. `harness/android_app/intel.py` (`harvest(app_root)`) is a
deterministic scan over the decoded tree; a real target's recon step runs it over
apktool/jadx output. See `targets/android-canary/intel` for the driver.

## Capability-gated checks — [`capabilities.md`](capabilities.md)

Not every check applies to every app. WebView-bridge hunting only makes sense with a
JS bridge; the ContentProvider track only with an exported/loosely-permissioned
provider; JNI ASan only with a *reachable* `.so`. So the specialized checks are
**gated by an inventory of the target's shape**: the `threat-model` skill records a
capability inventory in `THREAT_MODEL.md` §9 (`present` ∈ `yes|no|test_only|partial`
+ evidence) and its machine twin `capabilities.json`, and
[`capabilities.md`](capabilities.md) maps each capability to the scan §A section, the
oracle, the promotion path, and the triage rules it turns on across every stage. An
absent capability is a deliberate, evidenced skip. `harness/capabilities.py` `_GATES`
is the code twin of that table — the routing is programmatic, not a reviewer reading
the table by hand.

## Two layers (use either or both)

### 1. Interactive skills — usable today, zero setup

Tune the read-only `/vuln-scan` and `/triage` skills for Android with the two
plain-text files here — **no Docker, no code execution, no device required**:

```
/vuln-scan <decompiled_apk_dir> --extra profiles/android-app/scan-extras.txt
/triage <findings>.json --fp-rules profiles/android-app/fp-rules.txt
```

- **[`scan-extras.txt`](scan-extras.txt)** appends the §A1–§A9 review brief to the
  scan: IPC/exported (§A1), Intent/PendingIntent/deeplinks (§A2), WebView/JS-bridge
  (§A3), storage/data-leakage (§A4), TLS/cleartext/NSC (§A5), ContentProvider (§A6),
  dynamic-code/reflection/deser (§A7), build-config (§A8), native/JNI reachability
  (§A9). Each section is stated as entry points, sinks, and guards, with a
  DO-NOT-REPORT list and the trust-boundary rule (name the attacker-controlled
  entry for every finding; everything the scan emits is strength 1).
- **[`fp-rules.txt`](fp-rules.txt)** appends the **AR1–AR9** triage precedents: AR1
  (signature-permission-gated exported component → FP), AR3 (loopback cleartext → FP),
  AR4 (public "secret" → FP), AR5 (correctly-scoped provider grant → FP), the reverse
  calibration AR6 (a *reachable* config issue is real, not "just hardening") and AR7
  (dynamic load / reflection / deser of attacker input is real), and — the load-
  bearing one — **AR8**, the strength/DISPOSITION gate: strength-1 non-terminal →
  `contested`; only `STATIC_TERMINAL_CLASSES` → `real_latent_static_argument`; the
  agent never self-declares terminal. AR2 (debug-variant build-config is context, not
  auto-FP) and AR9 (native/JNI needs the reachability chain) round it out.

This is the recommended starting point and, for many reviews, sufficient on its own.

### 2. Autonomous pipeline — the `android-app` profile

The profile bundles the Android-specific pieces the generic orchestration
(find → grade → judge → report) resolves at run time. Because a witness rides *inside*
a `CrashArtifact`, the generic rail is unchanged — only the swappable nouns differ:

| piece | base (`cpp`) | `android-app` |
|---|---|---|
| find prompt | `harness/prompts/find_prompt.py` | [`harness/android_app/find_prompt.py`](../../harness/android_app/find_prompt.py) — hunt the entry→sink graph; emit a WITNESS |
| detector | `harness/asan.py` | [`harness/android_app/detect.py`](../../harness/android_app/detect.py) — parses the WITNESS header; `project_frames` = sink-first path anchors; `crash_reason` = finding class |
| evidence model | crash (implicit strength 4) | [`harness/witness.py`](../../harness/witness.py) — `SecurityWitness`, strength 1..4, `default_disposition` |
| capability gates | `harness/capabilities.py` | same file — the android `_GATES` rows (§A1..§A9) |
| grade / judge / report | base rubric | base rail, witness-aware (a valid finding is a reachability witness, not a clean return) |

The dedup signature is `(finding_class, sink site)`: distinct sinks are distinct
findings; the same sink reached from several entries is one finding. A native crash
routed here (an android-native escalation) carries no WITNESS header, so
`crash_reason` falls back to the shared ASan summary regex and still dedups.

## Provenance / design decisions

The strength model, the two-tier promotion, the terminal-class set, and the native
gate are recorded as ADRs in `docs/profiles/android/DECISIONS.md`
(ADR-1 native-reachability gate, ADR-3 graph-not-checklist, ADR-4 explicit ranking /
anti-gaming, ADR-5 two dynamic cost tiers) and referenced from `harness/witness.py`.
The finding-class taxonomy and the AR triage precedents are grounded in the
OWASP MASVS/MASTG mobile controls (PLATFORM / STORAGE / NETWORK / CODE), attached to
each found path as metadata rather than as the search order.
