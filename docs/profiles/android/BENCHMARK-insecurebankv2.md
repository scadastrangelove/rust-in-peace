# Benchmark — InsecureBankv2 (real-app run)

First run of the `android-app` profile against a real deliberately-vulnerable
app, to measure recall outside the synthetic canary. Heavy steps (APK decompile)
ran on the build box; the analysis is the profile's own tools + an agentic MASTG
static scan.

- **Target:** [dineshshetty/Android-InsecureBankv2](https://github.com/dineshshetty/Android-InsecureBankv2) `InsecureBankv2.apk` (3.4 MB, 25 bundled `.so`, `com.android.insecurebankv2`).
- **Decompile:** `apktool d` → 6529 smali + decoded manifest (build box).
- **Intel:** `harness/android_app/intel.harvest()` on the decoded tree.
- **Scan:** 6 MASTG-category reviewers (union-of-N) over the app's own smali
  (`smali/com/android/insecurebankv2/`, 49 files) + the manifest, using
  `profiles/android-app/scan-extras.txt` and `fp-rules.txt`.

## Recall

**22 findings, 0 false positives.** Against the documented InsecureBankv2 vuln set:

| Documented vuln | Finding | Status |
|---|---|---|
| Flawed BroadcastReceiver (change-pw → SMS leaks decrypted password) | `broadcast-injection` HIGH | ✅ |
| Vulnerable exported Activities | `exported-activity-launch` ×3–4 | ✅ |
| Insecure WebView (file://, JS) | `webview-file-access` HIGH | ✅ |
| Weak/hardcoded crypto | hardcoded AES key + all-zero static IV | ✅ |
| Insecure ContentProvider (SQLi) | `content-provider-sqli` (null projectionMap) + `exported-no-permission` | ✅ |
| Insecure local storage (creds in SharedPrefs) | `insecure-storage-secret` (broken encryption) | ✅ |
| Insecure logging (creds/PII → logcat) | 3× logcat findings | ✅ |
| Insecure SDCard storage (world-readable statements) | `insecure-storage-secret` (external) | ✅ |
| Cleartext HTTP to backend | `cleartext-endpoint` ×3 + `cleartext-config` | ✅ |
| Developer backdoor (devadmin → /devlogin) | `hardcoded-backdoor-credential` | ✅ |
| Broken access control (change-pw any account) | ChangePassword (uname, no session) | ✅ |
| allowBackup / debuggable | `allow-backup` + `debuggable-flag` (terminal) | ✅ |
| Root detection & bypass | — | ⚪ out-of-static-scope → Tier-B dynamic |
| Emulator detection & bypass | — | ⚪ out-of-static-scope → Tier-B dynamic |
| Sensitive info in memory | — | ⚪ out-of-static-scope → Tier-B Frida |
| Username enumeration / parameter manipulation | — | ⚪ server-side → intel→EASM bridge |

**Static-track recall on app-side classes: 12/12 (100%).** Every miss is correctly
outside the static track's scope: three are RESILIENCE/runtime classes that need
`android-app-dynamic` (Tier-B, [DEVICE-SANDBOX.md](DEVICE-SANDBOX.md)), and two are
server-side classes that need the `intel.endpoints` → EASM/DAST bridge (ADR-7).
The profile's track split predicted this exactly.

## Why it's a good result, not just a high number

- **Zero FPs.** Every finding is a real issue with cited smali `file:line`.
- **Honest calibration** (the discipline the profile exists for): the DoTransfer
  reviewer *refuted its own brief* — "reads NO intent extras → unauthenticated
  reachability, **not** intent-driven transfer"; logcat findings were marked
  `reachable=false` (need adb/READ_LOGS, not peer-app-reachable).
- **DISPOSITION correct (ADR-4):** `content-provider-sqli` → `contested` (wants a
  Tier-A `content query` promotion); build-config → `real_latent_static_argument`
  (terminal); crypto/backdoor → `contested`.

## What the real app fixed in the tool

`intel.harvest` first returned **55 endpoints** — almost all from bundled SDKs
(googleads, doubleclick, analytics, PayPal); the "backend" `http://hostname` was
Google Play Services' tagmanager. Fix: scope endpoints/secrets to the app's own
package (commit `4009657`). Result: 55 → **0**, honestly — InsecureBankv2 hardcodes
no backend host (it builds the URL from a user-configured `serverip`/`serverport`,
paths `/login`, `/devlogin`). The exported-surface harvest (6 components, all
`perm:None`) was already correct.

## Deferred

- **DIVA:** payatu removed the prebuilt `diva-beta.apk` (source-only now); no
  releases, mirrors 404. Deferred — would add the two native/.so challenges
  (#12/#13) that exercise the `android-native` track. Build-from-source on the box
  is the path when wanted.
- **Follow-ups the run motivates:** a general androguard-backed reach oracle (so
  the autonomous `vuln-pipeline run --profile android-app` works on any APK, not
  just the canary's scripted `reach`); a dynamic-URL / path-fragment intel pass
  (InsecureBankv2's `/login`,`/devlogin` are useful server-side even with no
  hardcoded host).
