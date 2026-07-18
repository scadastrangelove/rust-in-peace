# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""find → promote bridge — the reattack stage for android-app.

The cpp/rust reattack turns a static finding into a *reproducing fuzz harness*;
the android analog is **not byte fuzzing**. A strength-1 `static_reachability`
witness (an argued entry→guard→sink path) is promoted to an *observed* effect by
driving the app on a device/emulator and watching the sink fire — raising the
witness to `dynamic_observation` (strength ≥ 2) or, for a bundled `.so`, to a JNI
`native_crash` (strength 4). The split mirrors rust's:

  1. dispatch(cwe/class, capability) → (kind, tier, domain, strength, plan)   deterministic, this file
  2. agent.bind(plan, finding) → a working adb/Frida/proxy PoC               program synthesis
  3. validate: observe the effect **3/3 deterministically** (the android
     analog of the 3/3 crash bar) — the device is the oracle

The determinism is in **dispatch and the 3/3 observation gate**, not in the PoC
authoring. This module owns steps 1 and 3 and produces the step-2 prompt
(`build_reattack`, wired as `Profile.build_reattack`). Dispatch routes by the
threat-model capability (ADR-5 cost tiers): exported IPC / deeplink / provider
and insecure-storage / cleartext are Tier A (light adb — `am`, `content`,
`logcat`, `run-as`, an intercepting proxy → strength 2); a WebView bridge or any
heavy multi-step observation is Tier B (Frida + emulator → strength 3); a
bundled `.so` escalates to the cpp/ASan JNI harness **only** when
`capabilities.run_android_native()` confirms the ADR-1 reachability chain
(strength 4).

A non-promotion is a *disposition*, not a failure (mirrors rust §5): the outcome
names WHY — `guard_held` (the observation refuted the path), `terminal` (a
build-config class in `witness.STATIC_TERMINAL_CLASSES`, nothing to observe →
`real_latent_static_argument`), or `contested` (no cheap stronger witness — the
strength-1 argument stands and wants promotion later). An agent never
self-declares a finding terminal (AR8): only the declared class set may be.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from .. import witness as _witness

DEFAULT_REATTACK_MAX_TURNS = 400
SMOKE_SECONDS = 90          # light-tier observation window: seconds to drive the
                            # interaction / tail logcat before calling a probe clean
RSS_LIMIT_MB = 4096         # heavy-tier (emulator + Frida) memory cap


@dataclass(frozen=True)
class Dispatch:
    """The deterministic promotion plan for one finding — the android twin of
    rust's `Dispatch`. `kind`/`tier`/`strength` are the witness fields the
    successful observation produces (see harness/witness.py); `plan` matches the
    `fuzz_rung` in capabilities._GATES so the routing has a paper trail."""
    kind: str                 # witness.KIND_* the observation yields
    tier: str | None          # light_adb | heavy_instrumented | None (static)
    domain: str | None        # behavior | network | storage | None (static)
    strength: int             # the strength a successful observation earns (1..4)
    plan: str                 # concrete PoC-plan id (== capabilities._GATES fuzz_rung)
    oracle: str               # human-readable oracle note

    @property
    def promotes(self) -> bool:
        """True when this plan can raise the witness above a static argument."""
        return self.strength >= 2

    @property
    def is_static(self) -> bool:
        return self.kind == _witness.KIND_STATIC_REACHABILITY


_KIND_DYN = _witness.KIND_DYNAMIC_OBSERVATION
_KIND_STATIC = _witness.KIND_STATIC_REACHABILITY
_KIND_NATIVE = _witness.KIND_NATIVE_CRASH

# ── the promotion plans (ADR-5 tiers; plan ids match capabilities._GATES) ─────
_ADB_INTENT = Dispatch(
    _KIND_DYN, "light_adb", "behavior", 2, "adb_intent_probe",
    "adb `am start`/`broadcast` a crafted Intent; observe the sink via logcat/return")
_ADB_DEEPLINK = Dispatch(
    _KIND_DYN, "light_adb", "behavior", 2, "adb_deeplink_probe",
    "adb `am start -a VIEW -d <uri>`; observe the redirected navigation/forward")
_ADB_PROVIDER = Dispatch(
    _KIND_DYN, "light_adb", "behavior", 2, "adb_provider_probe",
    "adb `content query`/`read` with a crafted URI+selection; observe rows/file bytes")
_ADB_STORAGE = Dispatch(
    _KIND_DYN, "light_adb", "storage", 2, "adb_storage_observe",
    "drive the flow, then `run-as`/`adb backup` and read the file for the secret")
_MITM_NET = Dispatch(
    _KIND_DYN, "light_adb", "network", 2, "mitm_network_observe",
    "route the request through an intercepting proxy; observe cleartext on the wire")
_FRIDA_BRIDGE = Dispatch(
    _KIND_DYN, "heavy_instrumented", "behavior", 3, "frida_bridge_hook",
    "Frida-hook the @JavascriptInterface method / load a page that reaches it")
_STATIC_ARG = Dispatch(
    _KIND_STATIC, None, None, 1, "static_argument",
    "no cheap dynamic observation (companion app / driven attacker input is heavy) "
    "— the strength-1 argument stands → contested")
_STATIC_TERM = Dispatch(
    _KIND_STATIC, None, None, 1, "static_terminal",
    "pure manifest/config property — nothing to observe beyond what is statically present")
_JNI_ASAN = Dispatch(
    _KIND_NATIVE, None, None, 4, "jni_libfuzzer_asan",
    "hand off to the cpp/ASan JNI harness — gated on capabilities.run_android_native() (ADR-1)")


# ── capability → plan (the dominant android routing signal) ───────────────────
_BY_CAPABILITY: dict[str, Dispatch] = {
    "exported_ipc": _ADB_INTENT,
    "deeplink_applink": _ADB_DEEPLINK,
    "content_provider": _ADB_PROVIDER,
    "insecure_storage": _ADB_STORAGE,
    "cleartext_tls": _MITM_NET,
    "webview_bridge": _FRIDA_BRIDGE,
    "pending_intent": _STATIC_ARG,
    "dynamic_code_load": _STATIC_ARG,
    "build_config_exposure": _STATIC_TERM,
    "android_native_code": _JNI_ASAN,
}

# ── finding-class → capability (so the `cwe` slot, which carries the android
# finding class here, can route when no explicit capability is passed) ─────────
_CLASS_TO_CAP: dict[str, str] = {
    "android:exported-activity-launch": "exported_ipc",
    "android:exported-service": "exported_ipc",
    "android:broadcast-injection": "exported_ipc",
    "android:content-provider-sqli": "content_provider",
    "android:content-provider-traversal": "content_provider",
    "android:webview-js-bridge": "webview_bridge",
    "android:webview-file-access": "webview_bridge",
    "android:cleartext-endpoint": "cleartext_tls",
    "android:insecure-storage-secret": "insecure_storage",
    "android:deeplink-open-redirect": "deeplink_applink",
    "android:pending-intent-hijack": "pending_intent",
    "android:dynamic-code-load": "dynamic_code_load",
    # build-config terminals (witness.STATIC_TERMINAL_CLASSES) → the config track
    "android:missing-proguard": "build_config_exposure",
    "android:debuggable-flag": "build_config_exposure",
    "android:allow-backup": "build_config_exposure",
    "android:cleartext-config": "build_config_exposure",
    "android:exported-no-permission": "build_config_exposure",
    "android:backup-no-rules": "build_config_exposure",
    "android:test-only-flag": "build_config_exposure",
}


def _class_str(cwe: str | int | None) -> str:
    s = str(cwe or "").strip()
    return s if s.startswith("android:") else ""


def _cap_from_class(cwe: str | int | None) -> str | None:
    return _CLASS_TO_CAP.get(_class_str(cwe))


def dispatch(cwe: str | int | None,
             capability: str | None = None,
             structure_gated: bool = False) -> Dispatch:
    """Route a finding to a promotion plan (kind, tier, domain, strength, plan).

    Precedence (strongest signal first):
      explicit `capability` (the threat-model §9 mechanism — definitive);
      else the `cwe` slot read as an `android:<...>` finding class;
      else the honest default — a strength-1 argument that stays `contested`.

    `structure_gated` marks a light-adb observation that actually needs an
    instrumented (emulator/Frida) drive to reach the sink — it escalates the
    TIER (light → heavy, strength 2 → 3), not the finding class.
    """
    disp: Dispatch | None = None
    if capability and capability in _BY_CAPABILITY:
        disp = _BY_CAPABILITY[capability]
    else:
        cap = _cap_from_class(cwe)
        if cap is not None:
            disp = _BY_CAPABILITY[cap]
    if disp is None:
        disp = _STATIC_ARG
    if (structure_gated and disp.kind == _KIND_DYN and disp.tier == "light_adb"):
        disp = replace(
            disp, tier="heavy_instrumented", strength=3,
            oracle=disp.oracle + " (structure-gated → instrumented/Frida drive)")
    return disp


# ── step 2: the binding prompt (Profile.build_reattack) ───────────────────────
# The concrete PoC recipe per plan — the android analog of inlining rust's chosen
# harness template. Keyed on Dispatch.plan.
_PLAN_PLAYBOOK: dict[str, str] = {
    "adb_intent_probe": """\
# Exported component — craft the Intent an unprivileged 3rd-party app could send:
adb shell am start        -n <pkg>/<component> -a <action> --es <key> "<attacker-value>"   # Activity
adb shell am start-foreground-service -n <pkg>/<component> -a <action> ...                  # Service
adb shell am broadcast    -n <pkg>/<receiver>  -a <action> --es <key> "<attacker-value>"   # Receiver
adb logcat -d | grep -i <pkg>    # observe: sink fires / data returned / caller intent forwarded""",
    "adb_deeplink_probe": """\
adb shell am start -a android.intent.action.VIEW -d "<scheme>://<attacker-host>/<path>?<params>" <pkg>
# observe: did the app redirect to / load the attacker URI (open-redirect into a WebView / browser)?
adb logcat -d | grep -iE 'WebView|loadUrl|redirect|http'""",
    "adb_provider_probe": """\
adb shell content query --uri "content://<authority>/<path>" --where "<selection with a ' SQLi payload>"
adb shell content read  --uri "content://<authority>/<path>/../../databases/secret.db"   # path traversal
# observe: rows / file bytes you should NOT be able to read as an unprivileged caller""",
    "adb_storage_observe": """\
# 1) drive the flow that writes the secret (login / token refresh) via am/monkey/UI
# 2) read it back as the app, or via a backup, and confirm the datum is in cleartext:
adb shell run-as <pkg> cat /data/data/<pkg>/shared_prefs/<file>.xml
adb backup -f /tmp/b.ab <pkg>   # then unwrap the .ab (skip 24-byte header, zlib-inflate, untar)
# observe: the sensitive datum (token/PII/key) present unencrypted""",
    "mitm_network_observe": """\
# route device traffic through an intercepting proxy (mitmproxy/Burp) and drive the request:
adb shell settings put global http_proxy <proxy-host>:8080
# observe the request in cleartext on the wire (http:// or a downgraded/unpinned https).
# If TLS pinning blocks interception, ESCALATE to the heavy tier (Frida unpin) — strength 3.""",
    "frida_bridge_hook": """\
# emulator + Frida (heavy): hook the @JavascriptInterface method, then reach it from web content:
frida -U -n <pkg> -e 'Java.perform(function(){ /* hook <Bridge>.<method> */ });'
# or load attacker HTML that calls window.<bridge>.<method>(...) and observe the native call fire.
# a WebView with file access: load a file:// page that reads app-private files and observe the read.""",
    "static_argument": """\
# No cheap dynamic observation: a PendingIntent hijack needs a companion malicious app;
# a DexClassLoader / deserialization sink needs attacker input driven end-to-end.
# Re-confirm the static entry->sink path 3/3 with the reachability oracle. The witness
# stays kind=static_reachability strength=1; disposition = contested (wants promotion a
# light adb probe cannot give). OPTIONAL heavy escalation: if an emulator run CAN drive the
# attacker input into the load/deserialize sink under Frida, promote to strength 3.""",
    "static_terminal": """\
# A pure manifest/config property (allowBackup / debuggable / testOnly / permissive NSC /
# exported-without-permission / missing-proguard / backup-no-rules). There is nothing to
# dynamically observe beyond what the manifest/NSC already states. Confirm the attribute in
# AndroidManifest.xml / network_security_config.xml; the witness stays kind=static_reachability
# strength=1 with disposition real_latent_static_argument (a declared terminal class).""",
    "jni_libfuzzer_asan": """\
# ADR-1 gate: run ONLY if capabilities.run_android_native() is true
# (native_reachable_from_untrusted_input in {yes,partial}). Hand the CONFIRMED
# entry -> Java -> JNI -> attacker-arg chain to the cpp/ASan JNI harness: build a libFuzzer
# target that calls the exported JNI function with fuzzed args, compiled with -fsanitize=address.
# A crash is a native_crash witness (strength 4). A bare .so with no confirmed chain does NOT
# fuzz — emit verdict=contested, residual native_gated (a paper-trailed down-rank, not a skip).""",
}


REATTACK_PROMPT_TEMPLATE = """\
You are promoting a graded static Android finding from an *argued* reachability
path to an *observed* effect, as part of an authorized defensive assessment. A
table already picked your cost tier and observation plan; your job is the step a
table cannot do — bind the plan to THIS app on a real device/emulator and let the
observation gate the result. This is NOT byte fuzzing; the device is the oracle.

## Environment

Isolated sandbox with an Android device/emulator reachable over `adb`; network
egress otherwise blocked. The decompiled app from {github_url} (commit {commit})
is at {source_root}. Available: adb, am/pm, `content`, logcat, an intercepting
proxy, Frida (heavy tier only), python3.

## The finding

- Finding class: {cls}
- Capability / mechanism: {capability}
- Vulnerable sink site: {site}
- Notes: {mechanism}
{defer_section}
## Dispatched promotion plan

- Cost tier: **{tier}**   (ADR-5: light_adb = strength 2, heavy_instrumented = strength 3)
- Observation domain: {domain}
- Witness kind on success: **{kind}** (strength {strength})
- Plan: `{plan}` — {oracle}

Concrete recipe (adapt the placeholders to THIS app's package/component/authority):

```
{playbook}
```

## Validation protocol — the device is your oracle (3/3 or it isn't promoted)

1. Reproduce the entry: fire the crafted Intent / URI / query / request above.
2. **Observe the sink**: capture the effect (logcat line, returned rows/bytes, the
   file's cleartext datum, the plaintext request, the native call) within a
   {smoke_seconds}s observation window. The observed effect — not the fact that a
   command ran — is the witness. Heavy-tier runs cap the emulator at
   {rss_limit} MB so the budget is spent on the observation, not a runaway process.
3. **Determinism**: repeat until the observation is **3/3 identical** (the android
   analog of the 3/3 crash bar). A sometimes-fires effect is not yet promoted.
4. If the guard actually holds (the `am`/`content`/proxy attempt is rejected, the
   file is encrypted, the request is pinned+encrypted), the path is REFUTED — say
   so honestly (`guard_held`); do not dress a blocked probe as an observation.

## Emit the WITNESS the observation produced

On a successful observation, emit the promoted witness — same `class` and
`severity` as the finding, but the kind/strength/domain/tier this plan earned:

    {target_witness}
    entry: <the exported component / deeplink / provider / request>  AndroidManifest.xml
      --> <the observed hop>  <smali path:line>
    guard: <the guard that failed to stop it>
    sink:  <the sink you OBSERVED firing>  <smali path:line>
    observed: <the logcat line / rows / cleartext datum / native call — the evidence>

## A "not promoted" is a disposition, not a failure

If you cannot raise the strength this run, name WHY — never a bare "0 observed":
- `guard_held` — the observation refuted the path (the guard stops it); the finding
  is not real. This is a WIN for correctness.
- `terminal` — the class is a declared build-config terminal, so there is nothing
  to observe: the witness stays kind=static_reachability strength=1 with disposition
  **real_latent_static_argument**. Only these classes may be terminal — you do NOT
  get to self-declare a finding terminal (AR8): {terminal_classes}.
- `native_gated` — an `android_native_code` finding whose entry→Java→JNI→attacker-arg
  chain is NOT confirmed (a bare `.so`, ADR-1): do not fuzz JNI; down-rank.
- `device_unavailable` — no device/emulator to run the probe; the reason must be
  fixed and re-run, it is not a clean result.
- `contested` — the path holds statically but no cheap stronger witness is
  obtainable this run; the strength-1 argument stands and wants promotion later.

## Output format

When done, emit exactly these tags once:

<witness_path>/path/to/{fuzz_target}.observation</witness_path>
<verdict>promoted|native_crash|contested|terminal|guard_held</verdict>
<residual>promoted|native_crash|contested|terminal|guard_held|native_gated|device_unavailable</residual>
<strength>N</strength>
<domain>behavior|network|storage|-</domain>
<tier>light_adb|heavy_instrumented|-</tier>
<crash_output>
[the promoted WITNESS block above — header + entry/guard/sink + the observed:
evidence line — so the detector parses the stronger witness; OR the static
witness unchanged if contested/terminal, with the reason]
</crash_output>
<observation>the raw adb/logcat/proxy/Frida evidence lines</observation>
<detail>device/emulator, exact commands run, the guard bypassed, escalations</detail>

`<verdict>` MUST be `promoted` iff the emitted witness kind is dynamic_observation
with strength ≥ 2; `native_crash` iff strength 4; `terminal` only for a declared
static-terminal class; otherwise `contested` (or `guard_held` if refuted).
"""

_DEFER_SECTION = """\
- DEFER-TO-DYNAMIC sketch from the finder (an Intent/URI/observation the static
  stage argued but could not observe — drive THIS):
{defer_sketch}
"""


def build_reattack(
    *,
    github_url: str,
    commit: str,
    source_root: str,
    cwe: str | int | None,
    site: str,
    mechanism: str = "",
    capability: str | None = None,
    structure_gated: bool = False,
    defer_sketch: str | None = None,
    smoke_seconds: int = SMOKE_SECONDS,
    rss_limit_mb: int = RSS_LIMIT_MB,
    fuzz_target: str = "reattack",
) -> str:
    """Step-2 binding prompt for the android promotion agent (wired as
    `Profile.build_reattack`). Dispatches deterministically on capability/class,
    inlines the chosen observation recipe, and hands the agent the 3/3 device
    oracle protocol + the WITNESS the observation must produce."""
    disp = dispatch(cwe, capability, structure_gated)
    cls = _class_str(cwe) or "android:<finding-class>"
    cap_display = (capability or _cap_from_class(cwe) or "(inferred from class)")
    defer_section = (
        _DEFER_SECTION.format(defer_sketch=defer_sketch) if defer_sketch else "")
    # The witness the successful observation produces — same class/severity as the
    # finding (carried over), the kind/strength/domain/tier this plan earns.
    target_witness = (
        f"WITNESS: kind={disp.kind} strength={disp.strength} "
        f"severity=<carry over from the finding> class={cls} "
        f"domain={disp.domain or '-'} tier={disp.tier or '-'}"
    )
    terminal_classes = ", ".join(sorted(_witness.STATIC_TERMINAL_CLASSES))
    return REATTACK_PROMPT_TEMPLATE.format(
        github_url=github_url,
        commit=commit,
        source_root=source_root,
        cls=cls,
        capability=cap_display,
        site=site,
        mechanism=mechanism or "(none given — infer from the sink site)",
        defer_section=defer_section,
        tier=disp.tier or "-",
        domain=disp.domain or "-",
        kind=disp.kind,
        strength=disp.strength,
        plan=disp.plan,
        oracle=disp.oracle,
        playbook=_PLAN_PLAYBOOK.get(disp.plan, "# (no recipe — infer from the plan above)"),
        target_witness=target_witness,
        terminal_classes=terminal_classes,
        smoke_seconds=smoke_seconds,
        rss_limit=rss_limit_mb,
        fuzz_target=fuzz_target,
    )
