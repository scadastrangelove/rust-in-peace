# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""android-app find prompt — hunt entry→sink reachability over decompiled DEX.

This is the **authoritative** file for the profile's evidence format: it defines
the SecurityWitness the find-agent emits, which harness/android_app/detect.py
parses and grade/report/judge consume. The other android prompt builders align
to the WITNESS format defined here.

Contract with the rail (same shape as cpp/rust find):
  * The find-agent's "input" is a **candidate** — a hypothesized reachability
    path (entry component + sink + the smali hops between them), written to a
    file (`poc_path`).
  * The "oracle" (`binary_path`, an in-image reachability re-walker driven by
    `reattack_harness`/run_detectors.sh) re-validates the candidate
    deterministically and prints a WITNESS block, or `reject:` if the path does
    not hold. Determinism means 3/3 re-runs agree — the android analog of the
    3/3 crash bar.
  * `crash_output` is that WITNESS block; `crash_type` is its finding class.
"""
from __future__ import annotations

# The witness format the oracle emits and detect.py parses. Kept here (next to
# the prompt that teaches it) as the single source of truth.
WITNESS_HEADER_EXAMPLE = (
    "WITNESS: kind=static_reachability strength=1 severity=HIGH "
    "class=android:exported-activity-launch domain=- tier=-"
)

# Android entry points (attacker-controlled surface) and security-sensitive
# sinks — the graph the agent walks. MASVS/MASTG categories are attached to a
# found path as metadata (report/dedup), they are NOT the traversal order.
_ENTRY_POINTS = """\
- exported Activity / Service / BroadcastReceiver (manifest `android:exported`)
- ContentProvider (exported / weak `android:permission` / `grantUriPermissions`)
- deep link / App Link (`<intent-filter>` `<data android:scheme=...>`)
- PendingIntent handed to another app (mutable / implicit)
- WebView navigation + JS bridge (`addJavascriptInterface`, `loadUrl`, file access)
- imported file / content URI (`Intent.getData()`, `openFileDescriptor`)
- Binder / AIDL interface; notification action; external-storage / shared file"""

_SINKS = """\
- return of sensitive data to the caller; privileged operation on their behalf
- authenticated / token-bearing outbound API call; token or credential exposure
- file / SQLite / SharedPreferences access with attacker-influenced path or key
- intent forwarding (`startActivity`/`sendBroadcast` of a caller-supplied intent)
- WebView native method reached from loaded content; arbitrary URI/file open
- SQL / query built from attacker input; dynamic code load (DexClassLoader,
  reflection, deserialization) of attacker-controlled input"""


def build_find_prompt(
    github_url: str,
    commit: str,
    source_root: str,
    binary_path: str,
    focus_area: str | None = None,
    known_bugs: list[str] | None = None,
    found_bugs_path: str | None = None,
    accept_dos: bool = False,
    reattack_harness: str | None = None,
) -> str:
    focus = (
        f"\nFOCUS: concentrate this run on **{focus_area}**. Other entry points "
        f"are in scope only if the shortest path to a sink runs through them.\n"
        if focus_area else "\n"
    )
    known = ""
    if known_bugs:
        known = "\nKnown planted/expected issues (confirm reachability, don't take on faith):\n" + \
                "\n".join(f"  - {b}" for b in known_bugs) + "\n"
    dedup = ""
    if found_bugs_path:
        dedup = (
            f"\nBefore submitting, read `{found_bugs_path}` (every finding submitted "
            "so far). Only add a finding if its (finding-class, sink site) is not "
            "already there; state in `dup_check` why yours is distinct.\n"
        )

    return f"""\
You are a mobile application-security reviewer auditing a **decompiled Android
app** for vulnerabilities that are *reachable from an attacker*. This is not a
memory-safety hunt: the bugs that matter here are logic / IPC / configuration /
platform issues in the app's own Dalvik code and manifest.

# The artifact
The target is the decompiled tree of an APK under `{source_root}` (upstream
{github_url} @ {commit}). Expect: `AndroidManifest.xml` (decoded), `smali/` (the
faithful bytecode representation — cite THIS for line refs), a jadx Java-ish
decompile (readable, but lossy — cross-check against smali), and `resources/`.
There is **no recompilable source and no compiler in the loop** — you reason
over the artifact, you do not rebuild it.
{focus}
# How to hunt: walk the entry→sink graph
Your organizing principle is a reachability graph, NOT a checklist. Enumerate the
attacker-controlled **entry points**, then trace control/data flow to a
security-sensitive **sink**, and decide whether a **guard** (permission,
`protectionLevel`, signature check, input validation, `exported=false`) actually
stops it.

Entry points:
{_ENTRY_POINTS}

Sinks:
{_SINKS}

A finding is a concrete path: `entry → (hops) → sink`, with the guard analysis
explicit. The MASVS/MASTG category (STORAGE, PLATFORM, NETWORK, …) is a *label*
you attach for the report — it does not drive the search.
{known}{dedup}
# Confirm each candidate with the reachability oracle
For each hypothesized path, write a **candidate** file describing it (entry
component, the smali hops with `file:line`, the guard, the sink) and validate it:

    {binary_path} <candidate_file>

The oracle deterministically re-walks the path and prints a WITNESS block if it
holds, or a line starting with `reject:` if it does not (guard blocks it, sink
not actually reached, entry not really exported). Run it until you get **3/3
identical** WITNESS results before submitting — a path that only sometimes
validates is not yet a finding.

# The WITNESS you submit (this exact format — the pipeline parses it)
Put the oracle's WITNESS block in `<crash_output>`. It is one header line then
the path:

    {WITNESS_HEADER_EXAMPLE}
    entry: com.app.ExportedActivity (exported=true, no permission)  AndroidManifest.xml
      --> smali/com/app/ExportedActivity.smali:42  onCreate reads getIntent().getData()
    guard: none
    sink:  startActivity(forwarded caller intent)  smali/com/app/ExportedActivity.smali:88

Header fields:
  * `kind`     — `static_reachability` for a code-reachability argument (what you
                 produce here). The dynamic stage may later promote it.
  * `strength` — **1** for a static reachability argument. Do NOT claim higher;
                 strength ≥ 2 requires an *observed* dynamic effect, which is the
                 grade/reattack stage's job, not yours.
  * `severity` — impact if exploited (`INFO|LOW|MEDIUM|HIGH|CRITICAL`), ORTHOGONAL
                 to strength. A reachable token exfil is HIGH even at strength 1.
  * `class`    — a stable finding-class id, `android:<kebab>` (e.g.
                 `android:exported-activity-launch`, `android:webview-js-bridge`,
                 `android:content-provider-sqli`, `android:cleartext-endpoint`,
                 `android:insecure-storage-secret`, `android:deeplink-open-redirect`,
                 `android:pending-intent-hijack`, `android:dynamic-code-load`).

# Honesty guardrails (these are load-bearing)
- **Reachability is the claim.** "This method looks unsafe" is not a finding
  unless an attacker-controlled entry reaches it past the guards. If you cannot
  trace the path, DEFER it — say so in `dup_check`, do not submit a strength-1
  guess dressed as confirmed.
- **A guard that holds kills the finding.** An `exported` component protected by
  a signature/`protectionLevel` permission, cleartext limited to `localhost`, a
  provider with correctly scoped `grantUriPermissions` — these are NOT vulns.
  Reject them; the oracle will too.
- **Do not inflate strength.** Everything you submit here is strength 1
  (argued). Downstream stages decide whether it promotes to observed.
- **Build-config findings** (missing ProGuard, `allowBackup`/`debuggable`/
  `testOnly`, permissive cleartext config) are legitimate but terminal — class
  them `android:<...>` from the build-config set and keep severity honest (these
  are usually LOW/MEDIUM hardening, not live exploits).

Submit one finding at a time: the candidate file as the PoC, the WITNESS block as
`<crash_output>`, the finding class as `<crash_type>`, and your reachability
reasoning (and dup justification) in `<dup_check>`.
"""
