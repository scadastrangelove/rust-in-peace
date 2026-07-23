<!--
Copyright 2026 Anthropic PBC
SPDX-License-Identifier: Apache-2.0
-->
# Dynamic-verification templates (find → promote)

Canonical, reviewable PoC skeletons for the **`android-app-dynamic`** promotion
stage. They are the concrete form of the inline recipes in
[`harness/android_app/find_to_fuzz.py`](../../../harness/android_app/find_to_fuzz.py)
`_PLAN_PLAYBOOK` — one file per `Dispatch.plan` id. The binding agent copies the
matching template, fills the `<PLACEHOLDERS>` for a specific app, and runs it in
the device sandbox (`docs/profiles/android/DEVICE-SANDBOX.md`).

A template does **not** just "run a command". Its job is to turn a strength-1
`static_reachability` *argument* into an **observed effect** — to watch the SINK
fire — and report that observation to the deterministic promotion engine
([`harness/android_app/promote.py`](../../../harness/android_app/promote.py)).
This is the Android analog of the cpp/rust reattack producing a reproducing crash;
here **the device is the oracle**, not a sanitizer.

## What each template emits — an `Observation`

Every template ends by printing an `OBSERVATION` block that maps 1:1 onto
`promote.Observation` — the load-bearing output the promotion engine consumes:

```
### OBSERVATION (feeds harness/android_app/promote.py :: Observation) ###
EFFECT_OBSERVED=<true|false>   # did the SINK actually fire / the datum actually appear?
RUNS=<n>                       # identical observations (the 3/3 determinism count)
OF_RUNS=<n>                    # attempts (the determinism bar is 3/3 — promote.DET_BAR)
GUARD_BLOCKED=<true|false>     # the probe was REJECTED by a guard → path REFUTED
DEVICE_AVAILABLE=<true|false>  # a device/emulator answered adb
EVIDENCE=<one-line raw logcat / rows / cleartext / navigation line>
```

`promote.promote()` reads these fields directly:

- `EFFECT_OBSERVED=true` **and** `RUNS==OF_RUNS>=3` → the observation is
  *deterministic* → the witness promotes to `dynamic_observation` (strength 2) and
  the finding becomes **`confirmed`**.
- `EFFECT_OBSERVED=true` but `RUNS<3` → **flaky**, stays `contested` (a
  sometimes-fires effect is not yet a witness).
- `GUARD_BLOCKED=true` → the guard actually stopped the probe → the path is
  **REFUTED** → `guard_held`. **This is a correctness WIN, not a failed run** — do
  not dress a blocked probe up as an observation. Report it honestly.
- `DEVICE_AVAILABLE=false` → `device_unavailable`: the reason must be fixed and
  re-run, it is not a clean result.

The `3/3` bar is deliberate — it is the Android twin of the cpp/rust 3/3 crash
bar (`promote.DET_BAR`). `RUNS` counts **identical** observations: the same
logcat marker, the same rows, the same cleartext datum — not merely three
non-empty outputs.

## Tier A vs Tier B (ADR-5 cost tiers)

| tier | witness kind | strength | how | where |
|---|---|---|---|---|
| **A — light adb** | `dynamic_observation` / `light_adb` | **2** | `am` / `content` / `run-as` / `adb backup` / `logcat` / `settings` — no instrumentation | **the four scripts here** (+ `mitm_observe.md`) |
| **B — heavy instrumented** | `dynamic_observation` / `heavy_instrumented` | **3** | Frida + emulator, instrumented MITM | `webview_bridge_hook.js`, `tls_unpin.js` (Tier-B set) |

An observation at *either* tier moves the finding to `confirmed`; Tier B just
earns a higher strength (harder-to-fabricate evidence). A `light_adb` plan that
turns out to need an instrumented drive to reach the sink is escalated by
`dispatch(..., structure_gated=True)` — light → heavy, strength 2 → 3.

## Plan-id → file map

| `Dispatch.plan` | capability | tier | file |
|---|---|---|---|
| `adb_intent_probe` | `exported_ipc` | A (s2) | [`intent_probe.sh`](intent_probe.sh) |
| `adb_deeplink_probe` | `deeplink_applink` | A (s2) | [`deeplink_probe.sh`](deeplink_probe.sh) |
| `adb_provider_probe` | `content_provider` | A (s2) | [`provider_probe.sh`](provider_probe.sh) |
| `adb_storage_observe` | `insecure_storage` | A (s2, storage) | [`storage_observe.sh`](storage_observe.sh) |
| `mitm_network_observe` | `cleartext_tls` | A (s2, network) | `mitm_observe.md` *(network set; `tls_unpin.js` for the Tier-B pinning escalation)* |
| `frida_bridge_hook` | `webview_bridge` | B (s3) | `webview_bridge_hook.js` *(Tier-B set)* |
| `static_argument` | `pending_intent`, `dynamic_code_load` | — (s1) | no PoC — stays `contested` (see `_PLAN_PLAYBOOK`) |
| `static_terminal` | `build_config_exposure` | — (s1) | no PoC — `real_latent_static_argument` (manifest is the evidence) |
| `jni_libfuzzer_asan` | `android_native_code` | native (s4) | handed to the cpp/ASan JNI harness — gated on `capabilities.run_android_native()` (ADR-1) |

The four scripts in this directory are the Tier-A (`light_adb`, strength 2)
templates: `intent_probe.sh`, `deeplink_probe.sh`, `provider_probe.sh`,
`storage_observe.sh`. The `static_*` and `jni_*` plans have **no PoC template** by
design — a static plan has nothing to dynamically observe, and the native plan
hands off to the C/C++ profile's libFuzzer+ASan harness.

## Conventions

- `<PLACEHOLDERS>` (angle brackets) are the holes the agent fills for the target:
  `<pkg>`, `<component>`, `<authority>`, `<scheme>`, `<attacker_host>`, and the
  `<sink_marker>` / `<secret_regex>` that proves the sink fired. Each script
  collects them in an editable block at the top.
- Every script does its own 3/3 loop and prints the `OBSERVATION` block; nothing
  else parses stdout.
- These are for **authorized defensive assessment** on an app you are permitted to
  test, in an isolated sandbox with network egress blocked.
