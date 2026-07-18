# android-canary — android-app pipeline demo target

A **synthetic decompiled Android app** (`com.canary.app`) used to self-check the
`android-app` profile — the mobile application-security fork of the pipeline. It
is the android analog of `targets/rust-canary`: it validates that the profile's
*plumbing* (find prompt + reachability-witness detector + capability gates +
DISPOSITION honesty gate) is wired correctly, not that any real app is vulnerable.

> There is **no real APK** and no upstream repo. `app/` is a hand-authored
> decoded tree (a decoded `AndroidManifest.xml` + `smali/`), which is all a real
> android target ships anyway (apktool/androguard decode the APK into exactly
> this shape). `config.yaml`'s `github_url`/`commit` are placeholders.

## The oracle is a reachability WITNESS, not a crash

The android-app profile has no sanitizer and no crash. Its oracle, `/work/reach`
(`binary_path`), takes a **candidate** path file and deterministically re-walks
the manifest + smali, printing either a `SecurityWitness`
(`kind=static_reachability strength=1 …`, exit 1 — the path holds) or a single
`reject:` line (exit 0 — a guard blocks it / the sink is not reached; graceful,
**not** a finding). `strength 1` is a static *argument*; an *observed* dynamic
effect (adb/Frida) is strength ≥ 2 and is the grade/reattack stage's job, never
the oracle's. Determinism bar: `reach` is a pure function of the fixture, so 3/3
re-runs agree — the android analog of the 3/3 crash bar.

## What is planted (and the expected DISPOSITION)

| id | class | where | strength-1 disposition |
|----|-------|-------|------------------------|
| T1 | `android:exported-activity-launch` | `ExportedForwardActivity.onCreate` forwards `getIntent().getData()` via `startActivity` | **contested** → dynamic-promotable |
| T2 | `android:debuggable-flag` | `<application android:debuggable="true">` | **real_latent_static_argument** (terminal) |
| T3 | `android:allow-backup` | `<application android:allowBackup="true">` | **real_latent_static_argument** (terminal) |
| T4 | `android:cleartext-config` | `<application android:usesCleartextTraffic="true">` | **real_latent_static_argument** (terminal) |
| DECOY | (naive: `android:exported-no-permission`) | `GuardedForwardActivity` — same forwarding code, signature-permission gated | **REJECTED** (AR1) |

The DISPOSITION column is the point of the canary. T1 is a reachability finding,
so at strength 1 it defaults to `contested` — it must earn promotion via an
observed dynamic effect before it counts as confirmed (ADR-4 anti-gaming). T2–T4
are pure build-config properties in `witness.STATIC_TERMINAL_CLASSES`, so they
are legitimately `real_latent_static_argument` at strength 1 (nothing to observe
beyond the manifest) — separately tagged, never merged with observed findings.

The **DECOY** matters as much as the findings. `GuardedForwardActivity` is
byte-for-byte the same forwarding code as T1; the only difference is the manifest
`android:permission` pointing at a `protectionLevel="signature"` permission, so
an arbitrary attacker app cannot reach it. Its naive label,
`android:exported-no-permission`, is itself a *terminal* class — accepting it
would wrongly skip promotion — so a rigorous oracle must **reject** it because the
guard holds (AR1 / AR8, the android F-018). `reach` never even opens its smali;
it stops at the permission check.

## Poke it by hand

```bash
# in this dir — reach resolves the decoded tree via APP_ROOT
APP_ROOT=app ./reach candidates/exported-activity-launch.txt   # -> WITNESS (exit 1)
APP_ROOT=app ./reach candidates/decoy-guarded.txt              # -> reject: guarded by signature permission
APP_ROOT=app ./reach candidates/debuggable-flag.txt           # -> WITNESS, class=android:debuggable-flag
APP_ROOT=app ./reach candidates/allow-backup.txt              # -> WITNESS, class=android:allow-backup
APP_ROOT=app ./reach candidates/cleartext-config.txt          # -> WITNESS, class=android:cleartext-config
```

A candidate file carries only two things the oracle trusts — the claimed `class:`
and the `entry:` component. The exported flag, the permission gate, and every
smali `file:line` in the emitted witness are **re-derived** from `app/`, so an
agent cannot self-declare a guarded component reachable or relabel a reachable
bug as terminal (ADR-4 / AR8).

## Via the full image (what the pipeline does)

```bash
docker build -t vuln-pipeline-android-canary:latest targets/android-canary
# inside the container:
/work/reach /work/candidates/exported-activity-launch.txt     # single candidate
mkdir -p /poc && cp /work/candidates/*.txt /poc/              # seed the re-attack set
/work/run_detectors.sh                                        # re-attack: sweep /poc/*
```

`run_detectors.sh` is the `reattack_harness`: with an argument it validates one
candidate; with none it sweeps `/poc/*` and exits 1 if any path still holds — the
android analog of "the crash still reproduces" (a fix that adds the guard flips
the witness to `reject:`, exit 0).

## Intel — the target-intelligence sibling (`intel.json`)

Beyond the `reach` oracle (findings), the canary ships an `intel` driver that
harvests the app's *intelligence* — endpoints, hosts, SDKs, permissions, deep
links, exported surface, secrets observed:

```sh
# in this dir — writes intel.json (or prints it with no arg)
APP_ROOT=./app ./intel intel.json
```

It surfaces two endpoints (`https://api.canary.example/v1/sync` and the cleartext
`http://legacy.canary.example/ping`), the OkHttp SDK, the `INTERNET` permission,
the `canary://` deep link, both exported activities, and one redacted
`google_api_key` — the endpoints being the discovery vector for server-side
testing. The fake maps-key value is never written to `intel.json`.

## Dynamic promotion — `android-app-dynamic` (simulated, no device)

The static `reach` oracle yields strength-1 witnesses. The dynamic stage promotes
them to *observed* effects (strength 2/3) by driving the app on an emulator in the
device sandbox (`docs/profiles/android/DEVICE-SANDBOX.md`). The canary has no
emulator, so `run_dynamic` **replays recorded observations** (`observations/*.json`)
through the real promotion engine (`harness/android_app/promote.py`) — proving the
path in CI:

```sh
./run_dynamic                       # replay every observation; each self-checks
./run_dynamic webview-js-bridge     # one, by fixture stem
```

| finding | observation | outcome |
|---|---|---|
| `exported-activity-launch` | adb `am start` forwards the URI (3/3) | **promoted** → strength 2 `light_adb` |
| `cleartext-endpoint` | mitmproxy sees cleartext to `legacy.canary.example` (3/3) | **promoted** → strength 2 `network` |
| `webview-js-bridge` | Frida observes `bridge.getToken()` fire (3/3) | **promoted** → strength 3 `heavy_instrumented` (Tier B) |
| `allow-backup` | nothing to observe (build-config) | **terminal** → `real_latent_static_argument` |
| `decoy-guarded` | `am start` rejected — signature permission | **guard_held** (refuted, even dynamically) |

A real target swaps the recorded observation for a live adb/Frida run; the engine
and the 3/3 determinism bar are identical.

## Where the canary simplifies vs a real target

`reach` uses stdlib XML + line grep over the fixture. A real android target keeps
the identical witness format and exit contract but swaps that body for
**androguard** over the decoded APK (real DEX control-flow for the entry→sink
walk, binary-XML manifest parsing, `<intent-filter>`/`grantUriPermission`
analysis). The Dockerfile installs androguard to mirror that; the canary just
doesn't need it.
