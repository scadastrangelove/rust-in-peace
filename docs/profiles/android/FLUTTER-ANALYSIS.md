# Flutter (and cross-platform) targets — the Dart-AOT analysis path

The android-app static layer reads Dalvik **smali**. For a Flutter app that is the
wrong artifact: the business logic (storage, TLS, routing, auth) is compiled to
**Dart AOT** inside `lib/**/libapp.so`, and the smali is thin glue. A smali/resource
scan is therefore blind, and its host list is bundled-library noise. This doc is the
runbook for the branch that handles it. (React-Native / Xamarin / Unity / Cordova
are detected too; only Flutter has the full Dart extractor documented here.)

## 1. Detect the stack (automatic)

`harness/android_app/stack.py::classify()` classifies the decoded tree from file
presence alone (`libflutter.so` + `libapp.so` + `assets/flutter_assets/` ⇒
`flutter`). `intel.harvest` consumes it: for any `stack != native-smali` it
**demotes smali/resource hosts to low confidence** and, for Flutter, reads the real
endpoints/secrets out of `libapp.so` via a pure-Python `strings` pass. So
`intel.hosts` is the real Dart backend surface, not glue noise. No setup needed —
this runs in recon.

## 2. Recon the blob cheaply (always, first)

```
strings -n 6 lib/arm64-v8a/libapp.so | grep -Ei 'https?://|token|encryptedSharedPref|badCertificate'
```

`strings` is not optional and it is not redundant with a decompiler: the object-pool
dump (below) is **not** a complete list of the binary's strings — a hardcoded URL /
token / id can be in the binary yet absent from the pool (a hardcoded document URL can
be missed exactly this way). Always raw-`strings` and cross-check.

Markers worth noting: `_onBadCertificateWrapper` is the **dart:io built-in present in
every Flutter app — NOT a finding**; `encryptedSharedPreferences` = good;
`flutter_inappwebview` + `onReceivedServerTrustAuthRequest` = a WebView TLS callback
to inspect (§AF1).

## 3. Decompile the Dart snapshot (Blutter)

[Blutter](https://github.com/worawit/blutter) dumps the Dart snapshot to
`pp.txt` (class/field/method + string pool), `objs.txt`, `asm/<pkg>/…` (per-library
disassembly annotated with Dart-level `bl …; [package] Class::method` calls), and a
`blutter_frida.js`.

**Two non-obvious build blockers (both fixed once, then reusable):**

1. **capstone must be 5.0.1, NOT master/6.x.** 6.x/"next" renamed the AArch64 API
   (`arm64_reg`→`aarch64_reg`, `ARM64_*`→`AARCH64_*`); Blutter is pinned to the 5.x
   `arm64_*` names → compile fails with "`arm64_reg` does not name a type". Build
   5.0.1 from source into a local prefix (no sudo):
   `git -C capstone checkout 5.0.1 && cmake -B build -DCMAKE_INSTALL_PREFIX=$HOME/local -DCAPSTONE_BUILD_SHARED=ON && cmake --build build -j && cmake --install build`.
2. **CMakeLists include path.** Blutter's `#include <capstone.h>` (bare) needs the
   `.../include/capstone` subdir on the line; patch its `CMakeLists.txt`
   `include_directories(AFTER ${CAPSTONE_INCLUDE_DIRS} ${CAPSTONE_INCLUDEDIR}/capstone)`.
3. Python deps in a venv (`pyelftools capstone requests`) — PEP-668 blocks system pip.

Run:
```
PKG_CONFIG_PATH=$HOME/local/lib/pkgconfig LD_LIBRARY_PATH=$HOME/local/lib \
  <venv>/bin/python blutter.py <decoded>/lib/arm64-v8a <out>
```

Method for a finding: grep `pp.txt` for the marker, then TRACE the sink in `asm/`
— do not infer a sink from string co-presence. `reFlutter` is the dynamic
alternative (repackage + MITM) when a device run is authorized.

## 4. The sinks that matter (mirrors scan-extras §AF)

- **§AF1 — two TLS stacks.** `dart:io` `HttpClient.badCertificateCallback` (API/Dio)
  AND `flutter_inappwebview` `onReceivedServerTrustAuthRequest` (WebViews) are
  independent. Enumerate **every** WebView. A handler returning
  `ServerTrustAuthResponse(PROCEED)` is accept-all. **Dedup proof:** the AOT is built
  with `dedup_instructions`, so ONE shared closure reused across N different-host
  WebViews cannot contain a per-host check ⇒ constant `return PROCEED` ⇒ unconditional
  accept-all (a HIGH — no trusted CA needed). PROCEED=`(1,1)`, CANCEL=`(0,0)`.
- **§AF2 — storage.** Hive `openBox` without a `HiveAesCipher` anywhere = plaintext
  tokens; `flutter_secure_storage` = Keystore-backed. Trace `<Repo> → putValue/write
  → openBox / setString`.
- **§AF3 — route guards.** `auto_route`: empty `List<AutoRouteGuard>(0)` on every
  route + no `AutoRouteGuard` impl = no route-level auth; then find where the
  PIN/biometric lock lives (a Splash `navigateToPincode`, not a guard/overlay ⇒
  deeplink may skip it — needs a 1-command dynamic confirm).

## 5. Scope + honesty

Static only unless a dynamic run is explicitly authorized; never install/run the
APK otherwise. Never probe a live third-party endpoint (e.g. an IDOR candidate on a
production host) — hand the operator a recipe against their own account instead. The
accept-all WebView finding (§AF1) IS static-definitive via the dedup argument; the
deeplink app-lock bypass (§AF3) is plausible-pending-dynamic — state each at its true
confidence.
