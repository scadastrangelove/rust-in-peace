# Threat model — android-canary

Format matching the `/threat-model` output shape, so `/vuln-scan` can consume it.
This is a SYNTHETIC decompiled-APK fixture (no real APK), the android analog of
`targets/rust-canary`.

## 1. Overview

`android-canary` is the decoded tree of a hypothetical Android app
(`com.canary.app`): a decoded `AndroidManifest.xml` plus `smali/` for two
Activities. There is no recompile and no emulator — a reviewer (and the pipeline)
reason over the artifact. The oracle is a **reachability witness**, not a crash.

## 2. Assets

- Integrity of the app's navigation / IPC surface (intent redirection lets a
  hostile app steer where the app goes).
- App-private data at rest (adb backup) and in transit (cleartext HTTP).
- The debug surface exposed by a `debuggable` release build.

## 3. Entry points & trust boundaries

| Entry point | Input | Trust |
|-------------|-------|-------|
| `ExportedForwardActivity` (`android:exported=true`, no permission) | caller `Intent` + its data URI | **untrusted** — any app on the device |
| `GuardedForwardActivity` (`android:exported=true`, `android:permission=…PRIVILEGED`) | caller `Intent` | **trusted-ish** — signature permission holds |
| `<application>` build-config flags | manifest (static) | attacker-observable, terminal |

The signature-level permission on `GuardedForwardActivity` **is** a trust
boundary: only same-signer apps hold it, so an arbitrary attacker app cannot
reach that component. `android:exported="true"` alone is not a vulnerability.

## 4. Threats

| # | Threat | Vector | Class | Impact |
|---|--------|--------|-------|--------|
| T1 | Intent redirection over IPC | exported, unguarded `ExportedForwardActivity.onCreate` reads `getIntent().getData()` and forwards it via `startActivity` with no allowlist | `android:exported-activity-launch` | HIGH (strength 1 → contested → dynamic-promotable) |
| T2 | Debuggable release | `<application android:debuggable="true">` | `android:debuggable-flag` | MEDIUM (terminal) |
| T3 | Backup exfiltration | `<application android:allowBackup="true">` | `android:allow-backup` | MEDIUM (terminal) |
| T4 | Cleartext traffic | `<application android:usesCleartextTraffic="true">` | `android:cleartext-config` | LOW (terminal) |

## 5. Out of scope / false positives

- `GuardedForwardActivity` — the SAME forwarding code as T1, but a signature
  permission gates it, so it is **not attacker-reachable**. The naive label is
  `android:exported-no-permission`; a rigorous oracle **rejects** it (AR1). It is
  the planted decoy, the point of the exercise as much as the real findings.
- Framework code (`android/*`, `androidx/*`) reached from the app — the finding
  is in the app's own smali, not the platform it calls.
