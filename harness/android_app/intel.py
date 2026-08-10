# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""TargetIntel — the non-vulnerability intelligence the android-app walk surfaces.

Distinct from a *finding* (a vulnerability witness): this is an inventory of the
app's outward shape — the server endpoints / hosts it talks to, the third-party
SDKs it bundles, the permissions it requests, its deep-link schemes, its exported-
component surface, its native libraries and defensive controls, and secrets
*observed* (recorded by kind + location, **never** stored). A C parser has none of
this; an app does, which is why the android-app profile is where the pipeline
grows a first-class intelligence artifact alongside its findings.

The **endpoints / hosts** list is the payload that bridges to server-side testing:
the mobile client enumerates the API hosts that a downstream EASM / DAST / passive-
DNS pipeline then attacks. Because that list drives *active* server testing, each
endpoint carries a ``confidence`` and ``source`` so the bridge never treats a
bundled-library resource string (or a Flutter glue-smali URL) as a real backend:

* **first-party app smali** → ``confidence=high`` (the app's own code);
* **resources / bundled framework** → ``confidence=low`` (may be library noise);
* **Dart AOT ``libapp.so``** (Flutter) → ``confidence=high`` (the real logic — a
  Flutter app's smali is glue, so we read the endpoints out of the Dart snapshot);
* known analytics/ad/crash CDNs → moved to ``telemetry_hosts``, out of ``hosts``.

``hosts`` is therefore the *clean, high-confidence, non-telemetry* server surface.

`harvest()` is a deterministic scan over a decoded APK tree (AndroidManifest.xml +
smali/ + lib/ + resources) — the canary runs it directly; a real target's recon
step runs the same harvester over apktool/jadx output. It is emitted as
`intel.json` next to a run's results.

Security note: secrets are logged by *kind* and *location* only (`redacted: true`)
— the artifact never carries the secret value, so intel.json is safe to share with
the server-side pipeline.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .stack import classify, NON_SMALI_STACKS

_ANDROID = "{http://schemas.android.com/apk/res/android}"


# ── data model ───────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Endpoint:
    host: str
    scheme: str                 # https | http | ws | wss | ftp …
    path: str | None            # first path seen, if any
    cleartext: bool             # scheme is a plaintext transport
    evidence: str               # where it was found
    confidence: str = "high"    # high (app code / Dart AOT) | low (resource / glue)
    source: str = "app-smali"   # app-smali | resource | libapp.so | *-glue

    def key(self) -> tuple[str, str, str | None]:
        return (self.scheme, self.host, self.path)


@dataclass(frozen=True)
class TargetIntel:
    endpoints: list[Endpoint] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)              # clean high-conf, non-telemetry
    telemetry_hosts: list[str] = field(default_factory=list)    # known analytics/ad/crash CDNs
    sdks: list[dict] = field(default_factory=list)              # {name, evidence, key_scope?}
    permissions: list[str] = field(default_factory=list)
    deeplinks: list[str] = field(default_factory=list)          # scheme:// or scheme://host
    exported_surface: list[dict] = field(default_factory=list)  # {component, type, permission|None}
    secrets_observed: list[dict] = field(default_factory=list)  # {kind, where, redacted: true}
    stack: str = "native-smali"                                 # runtime stack (see stack.py)
    native_libs: list[dict] = field(default_factory=list)       # {name, abi, path, size_bytes}
    signing: dict = field(default_factory=dict)                 # best-effort signature info
    defenses: list[dict] = field(default_factory=list)          # {kind, evidence, marker}

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["endpoints"] = [asdict(e) for e in self.endpoints]
        return d

    def write(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n")


# ── extraction helpers ───────────────────────────────────────────────────────
# A URL in a const-string / resource. Authority stops at /, ", or whitespace.
_URL = re.compile(r"\b(https?|wss?|ftp)://([A-Za-z0-9.\-]+(?::\d+)?)(/[^\s\"'\\]*)?")
_CLEARTEXT_SCHEMES = frozenset({"http", "ws", "ftp"})

# XML-namespace / documentation hosts that appear in decoded manifests and
# resources but are never a real app endpoint — dropped so intel.endpoints stays
# a clean server-surface list.
_NOISE_HOSTS = frozenset({
    "schemas.android.com", "www.w3.org", "xmlpull.org", "schemas.xmlsoap.org",
    "www.apache.org", "apache.org", "java.sun.com", "ns.adobe.com",
    "www.google.com",  # often a manifest/license boilerplate ref, not an endpoint
    # Dart/Flutter runtime & doc boilerplate that lives in the AOT snapshot / engine
    # .so — not an app backend (avoids engine strings surfacing as fake endpoints).
    "dartlang.org", "api.dart.dev", "dart.dev", "flutter.dev", "flutter.io",
    "www.unicode.org", "unicode.org", "spec.commonmark.org",
})

# Known analytics / ad / attribution / crash-reporting host suffixes. A match is
# NOT a finding and NOT a backend — it is telemetry; kept out of the clean `hosts`
# server-surface list (still recorded under `telemetry_hosts` so nothing is lost).
_TELEMETRY_HOSTS: tuple[str, ...] = (
    "doubleclick.net", "googlesyndication.com", "google-analytics.com",
    "googletagmanager.com", "googleadservices.com", "app-measurement.com",
    "crashlytics.com", "firebasecrashlytics.com", "firebase-settings.crashlytics.com",
    "appsflyer.com", "appsflyersdk.com", "onelink.me", "adjust.com", "adjust.io",
    "branch.io", "app.link", "sentry.io", "ingest.sentry.io", "bugsnag.com",
    "mixpanel.com", "amplitude.com", "flurry.com", "appmetrica.yandex.net",
    "mc.yandex.ru", "startappservice.com", "unity3d.com", "applovin.com",
    "facebook.com", "graph.facebook.com", "connect.facebook.net",
)

# Known SDK/library package prefixes → (display name, key-scope note|None).
# The key-scope note flags what an SDK's key normally IS, so an AR4 "public value"
# judgement is grounded rather than guessed. Extend as the corpus grows.
_SDK_PREFIXES: list[tuple[str, str, str | None]] = [
    ("com/google/firebase", "Firebase",
     "google_api_key is a PUBLIC client key (AR4) — abuse is gated by backend/App Check rules, not key secrecy"),
    ("com/google/android/gms/maps", "Google Maps SDK",
     "Maps API key is a browser/app-restricted PUBLIC key — verify SHA-1+package restriction is set"),
    ("com/google/android/gms", "Google Play Services", None),
    ("com/facebook", "Facebook SDK", "facebook_app_id is public; app_client_token is semi-secret — check"),
    ("com/squareup/okhttp", "OkHttp", None),
    ("okhttp3", "OkHttp", None),
    ("retrofit2", "Retrofit", None),
    ("com/amplitude", "Amplitude", "write-only client API key (public)"),
    ("com/mixpanel", "Mixpanel", "project token is a public client token"),
    ("io/sentry", "Sentry", "DSN is a public ingest key (public) but its host may leak internal infra"),
    ("com/crashlytics", "Crashlytics", None),
    ("com/appsflyer", "AppsFlyer", "devKey is semi-secret — attribution fraud if leaked; verify"),
    ("com/adjust/sdk", "Adjust", None),
    ("com/stripe", "Stripe", "publishable pk_ key is public; a sk_ secret key is CRITICAL if present"),
    ("com/yandex/metrica", "AppMetrica (Yandex)", None),
    ("io/appmetrica", "AppMetrica (Yandex)", None),
]

# Secret shapes. (label, compiled pattern) — matched against smali + resources +
# Dart AOT strings. We record kind + location only; the value is NEVER stored.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("stripe_secret_key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_or_jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("generic_api_key_assignment",
     re.compile(r"""(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)"""
                r"""["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']""")),
]

# Defensive-control markers (POSITIVE controls, not vulnerabilities). Recorded as
# an inventory so the report can state "root/Frida/Play-Integrity/pinning present,
# enforcement unverified" — the coverage the smali-centric walk otherwise misses
# (these usually live in a bundled RASP plugin's smali or a native .so).
#
# Markers are deliberately CODE-SHAPED (class/path/symbol tokens, not English
# words) so a decompiled comment or doc string that merely mentions "Frida" is not
# mistaken for an actual control — the android-canary's teaching comments are
# exactly this trap. `_scan_tree` also skips smali `#` comment lines for defenses.
_DEFENSE_MARKERS: list[tuple[str, re.Pattern[str]]] = [
    ("root_detection", re.compile(
        r"(isRooted|RootBeer|/system/xbin/su|/system/bin/su|/system/app/Superuser"
        r"|eu\.chainfire\.supersu|com\.topjohnwu\.magisk|magiskhide|\btest-keys\b)")),
    ("frida_detection", re.compile(
        r"(re\.frida\.server|frida-server|frida-gadget|frida[_-]agent|gum-js-loop"
        r"|LIBFRIDA|libfrida\.so|/data/local/tmp/(?:re\.)?frida|\b27042\b"
        r"|de\.robv\.android\.xposed|XposedBridge|XposedHelpers)")),
    ("emulator_detection", re.compile(
        r"(goldfish|ranchu|generic_x86|sdk_gphone|DEVICE_IS_EMULATOR|ro\.kernel\.qemu"
        r"|Genymotion|vbox86)")),
    ("play_integrity", re.compile(
        r"(IntegrityManager|requestIntegrityToken|StandardIntegrityManager"
        r"|com/google/android/play/core/integrity|SafetyNet|attestationChallenge)")),
    ("ssl_pinning", re.compile(
        r"(CertificatePinner|setPinnedCertificates|TrustKit|okhttp3/CertificatePinner"
        r"|network_security_config|sha256/[A-Za-z0-9+/=]{40,})")),
]

_ABI_DIRS = frozenset({
    "armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64", "mips", "mips64",
})


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root))
    except ValueError:
        return p.name


def _dedup(seq: list[str]) -> list[str]:
    seen: list[str] = []
    for s in seq:
        if s not in seen:
            seen.append(s)
    return seen


def _is_telemetry(host: str) -> bool:
    h = host.lower()
    return any(h == s or h.endswith("." + s) for s in _TELEMETRY_HOSTS)


def _conf_rank(c: str) -> int:
    return {"high": 2, "low": 1}.get(c, 0)


# A smali comment is `#`-to-EOL where the `#` is line-leading or follows
# whitespace; a `#` glued to a preceding char (e.g. inside `"flag#RootBeer"`) is
# part of a token, not a comment, and is kept.
_SMALI_COMMENT = re.compile(r"(^|\s)#.*$")


def _strip_smali_comments(body: str) -> str:
    """Drop `#`-to-EOL comments so a decompiled comment that merely *mentions* a
    defense token isn't counted as an actual control (defense scan only)."""
    return "\n".join(_SMALI_COMMENT.sub(r"\1", line) for line in body.splitlines())


def _sdk_key_scope(name: str) -> str | None:
    for _pref, disp, scope in _SDK_PREFIXES:
        if disp == name:
            return scope
    return None


# ── manifest ─────────────────────────────────────────────────────────────────
def _parse_manifest(app_root: Path) -> tuple[list[str], list[str], list[dict], str]:
    """(permissions, deeplinks, exported_surface, package) from AndroidManifest.xml.
    Missing/unparsable manifest → empty lists (the harvester never hard-fails)."""
    mf = app_root / "AndroidManifest.xml"
    if not mf.exists():
        return [], [], [], ""
    try:
        root = ET.parse(mf).getroot()
    except (ET.ParseError, OSError):
        # Unparsable OR unreadable (a dir named AndroidManifest.xml, perm-000, …):
        # the harvester never hard-fails — an unusable manifest is empty, not fatal.
        return [], [], [], ""

    package = root.get("package", "") or ""
    perms = [e.get(f"{_ANDROID}name", "") for e in root.iter("uses-permission")]
    perms = _dedup([p for p in perms if p])

    deeplinks: list[str] = []
    for data in root.iter("data"):
        scheme = data.get(f"{_ANDROID}scheme")
        host = data.get(f"{_ANDROID}host")
        if scheme:
            deeplinks.append(f"{scheme}://{host}" if host else f"{scheme}://")
    deeplinks = _dedup(deeplinks)

    exported: list[dict] = []
    for tag in ("activity", "service", "receiver", "provider"):
        for comp in root.iter(tag):
            if comp.get(f"{_ANDROID}exported") == "true":
                exported.append({
                    "component": comp.get(f"{_ANDROID}name", ""),
                    "type": tag,
                    "permission": comp.get(f"{_ANDROID}permission"),  # None if ungated
                })
    return perms, deeplinks, exported, package


# ── smali / resources scan ───────────────────────────────────────────────────
def _in_app_package(rel: str, app_pkg_path: str) -> bool:
    """True if a smali file belongs to the app's own package (not a bundled SDK).
    Endpoints/secrets are scanned only from app code + resources, so an ad/
    analytics SDK's URLs and keys don't pollute the app's server-surface intel —
    the same third-party/first-party split the SDK detector relies on. With no
    package (missing manifest) this is permissive (scan all), preserving behavior."""
    if not app_pkg_path:
        return True
    return f"/{app_pkg_path}/" in f"/{rel.replace(chr(92), '/')}"


def _add_endpoint(endpoints: dict[tuple, Endpoint], ep: Endpoint) -> None:
    """Insert, upgrading on a confidence tie-break so a high-confidence sighting
    (app smali / Dart AOT) wins over a low-confidence one (resource / glue)."""
    old = endpoints.get(ep.key())
    if old is None or _conf_rank(ep.confidence) > _conf_rank(old.confidence):
        endpoints[ep.key()] = ep


def _scan_tree(
    app_root: Path, app_pkg_path: str, stack: str,
) -> tuple[dict[tuple, Endpoint], list[dict], list[dict], list[dict]]:
    """(endpoints, sdks, secrets_observed, defenses). Endpoints/secrets: app-package
    smali + all non-smali resources. On a non-smali stack (Flutter/RN/…), smali is
    glue → its endpoints are demoted to low confidence (the real ones come from the
    logic blob). SDKs + defenses: the whole tree (they *want* the bundled packages)."""
    is_non_smali = stack in NON_SMALI_STACKS
    smali_conf = "low" if is_non_smali else "high"
    smali_src = f"{stack}-glue" if is_non_smali else "app-smali"
    # Resource confidence is stack-keyed: on a NATIVE app a URL in res/values or a
    # config .json is idiomatic first-party config (often the ONLY place the backend
    # text survives R8, since smali keeps just the resource id) → high. On a
    # non-smali stack (Flutter/RN) resources are bundled-framework noise → low, and
    # the real endpoints come from the logic blob instead.
    res_conf = "low" if is_non_smali else "high"

    endpoints: dict[tuple, Endpoint] = {}
    sdk_hits: dict[str, str] = {}
    secrets: list[dict] = []
    secret_seen: set[tuple[str, str]] = set()
    defenses: dict[str, dict] = {}

    text_files = [p for p in app_root.rglob("*")
                  if p.is_file() and p.suffix in (".smali", ".xml", ".json", ".properties", ".txt")]

    for p in text_files:
        rel = _rel(p, app_root)
        is_smali = p.suffix == ".smali"
        # SDK URLs/keys are third-party noise for the app's server surface: scan
        # endpoints/secrets only from the app's own smali (+ any resource file).
        if is_smali and not _in_app_package(rel, app_pkg_path):
            continue
        try:
            body = p.read_text(errors="replace")
        except OSError:
            continue

        conf = smali_conf if is_smali else res_conf
        src = smali_src if is_smali else "resource"
        for m in _URL.finditer(body):
            scheme, host, path = m.group(1), m.group(2), m.group(3)
            if host in _NOISE_HOSTS:
                continue
            _add_endpoint(endpoints, Endpoint(
                host=host, scheme=scheme, path=path,
                cleartext=scheme in _CLEARTEXT_SCHEMES, evidence=rel,
                confidence=conf, source=src))

        for kind, pat in _SECRET_PATTERNS:
            if pat.search(body) and (kind, rel) not in secret_seen:
                secret_seen.add((kind, rel))
                secrets.append({"kind": kind, "where": rel, "redacted": True})

        defense_body = _strip_smali_comments(body) if is_smali else body
        for kind, pat in _DEFENSE_MARKERS:
            if kind not in defenses:
                dm = pat.search(defense_body)
                if dm:
                    defenses[kind] = {"kind": kind, "evidence": rel, "marker": dm.group(0)[:40]}

    # SDKs: match package prefixes against smali *paths* (structural, low-noise).
    for p in app_root.rglob("*.smali"):
        rel = _rel(p, app_root).replace("\\", "/")
        for prefix, name, _scope in _SDK_PREFIXES:
            if f"/{prefix}" in f"/{rel}" and name not in sdk_hits:
                sdk_hits[name] = rel

    sdks = [{"name": n, "evidence": ev, **({"key_scope": _sdk_key_scope(n)} if _sdk_key_scope(n) else {})}
            for n, ev in sorted(sdk_hits.items())]
    return endpoints, sdks, secrets, sorted(defenses.values(), key=lambda d: d["kind"])


# ── Dart AOT (Flutter) string extraction ─────────────────────────────────────
# printable-ASCII runs ≥ 6 chars — a fast pure-Python `strings` (no external
# binary), for reading URLs/secrets out of a Flutter libapp.so Dart snapshot.
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")


def _blob_text(data: bytes) -> str:
    """A `strings`-equivalent text view of a binary blob for the URL/secret
    regexes: printable-ASCII runs (covers Dart `OneByteString` / Latin-1 URLs,
    the common case) PLUS a UTF-16LE decode (covers `TwoByteString` URLs/secrets
    the ASCII pass alone would miss). Regex-based — ~10-50× the byte-loop it
    replaced, so a 64 MB cap stays sub-second."""
    ascii_runs = b"\n".join(_ASCII_RUN.findall(data)).decode("ascii", "replace")
    # Decode UTF-16LE at BOTH byte alignments — a string's file offset can be even
    # or odd, and a fixed offset-0 stride would miss half of them.
    utf16 = (data.decode("utf-16-le", "ignore") + "\n"
             + data[1:].decode("utf-16-le", "ignore"))
    return ascii_runs + "\n" + utf16


def _scan_logic_blobs(
    app_root: Path, blobs: list[str], max_bytes: int = 64 * 1024 * 1024,
) -> tuple[dict[tuple, Endpoint], list[dict], list[dict]]:
    """(endpoints, secrets, defenses) extracted from a non-smali logic blob's
    strings (Flutter libapp.so, RN bundle). These are HIGH confidence — they are
    the app's real embedded strings, not bundled-resource noise."""
    endpoints: dict[tuple, Endpoint] = {}
    secrets: list[dict] = []
    secret_seen: set[tuple[str, str]] = set()
    defenses: dict[str, dict] = {}
    seen_names: set[str] = set()

    for rel in blobs:
        p = app_root / rel
        # A multi-ABI app ships byte-identical blobs per ABI — scan one basename.
        if not p.is_file() or p.name in seen_names:
            continue
        seen_names.add(p.name)
        try:
            data = p.read_bytes()[:max_bytes]
        except OSError:
            continue
        # RN bundle is text; libapp.so is ELF — string-extract either way.
        text = _blob_text(data) if p.suffix == ".so" \
            else data.decode("utf-8", "replace")
        for m in _URL.finditer(text):
            scheme, host, path = m.group(1), m.group(2), m.group(3)
            if host in _NOISE_HOSTS:
                continue
            _add_endpoint(endpoints, Endpoint(
                host=host, scheme=scheme, path=path,
                cleartext=scheme in _CLEARTEXT_SCHEMES, evidence=rel,
                confidence="high", source=p.name))
        for kind, pat in _SECRET_PATTERNS:
            if pat.search(text) and (kind, rel) not in secret_seen:
                secret_seen.add((kind, rel))
                secrets.append({"kind": kind, "where": rel, "redacted": True})
        for kind, pat in _DEFENSE_MARKERS:
            if kind not in defenses:
                dm = pat.search(text)
                if dm:
                    defenses[kind] = {"kind": kind, "evidence": rel, "marker": dm.group(0)[:40]}
    return endpoints, secrets, sorted(defenses.values(), key=lambda d: d["kind"])


# ── native libs / signing ─────────────────────────────────────────────────────
def _native_libs(app_root: Path) -> list[dict]:
    """Inventory every bundled lib/**/*.so with its ABI + size — the native
    attack surface the §A9 side-track needs a real list for (was only a boolean)."""
    out: list[dict] = []
    for p in app_root.rglob("*.so"):
        if not p.is_file():
            continue
        abi = p.parent.name if p.parent.name in _ABI_DIRS else None
        try:
            size = p.stat().st_size
        except OSError:
            size = None
        out.append({"name": p.name, "abi": abi, "path": _rel(p, app_root), "size_bytes": size})
    return sorted(out, key=lambda d: (d["name"], d["abi"] or ""))


def _signing(app_root: Path) -> dict:
    """Best-effort signature info from a DECODED tree. apktool strips the APK
    Signing Block, so v2/v3 scheme + the signer cert require the original .apk —
    we report exactly what is determinable and name what is missing (never guess a
    scheme/DN we can't see)."""
    metainf = None
    for cand in (app_root / "original" / "META-INF", app_root / "META-INF"):
        if cand.is_dir():
            metainf = cand
            break
    if metainf is None:
        return {"determinable": False,
                "note": "no META-INF in decoded tree; APK signature scheme (v1/v2/v3) "
                        "and signer certificate require the original .apk"}
    try:
        sig_files = sorted(p.name for p in metainf.iterdir()
                           if p.suffix.upper() in (".RSA", ".DSA", ".EC", ".SF"))
    except OSError:
        return {"determinable": False, "note": "META-INF present but unreadable"}
    v1 = any(n.upper().endswith((".RSA", ".DSA", ".EC")) for n in sig_files)
    return {"determinable": True, "v1_jar_signature": v1, "signature_files": sig_files,
            "note": "v1 (JAR) presence only; v2/v3 (APK Signing Block) and the signer DN "
                    "are stripped by apktool — parse the original .apk to confirm scheme/DN"}


# ── entry point ──────────────────────────────────────────────────────────────
def harvest(app_root: str | Path) -> TargetIntel:
    """Deterministically harvest TargetIntel from a decoded APK tree
    (`app_root` contains AndroidManifest.xml and smali/). Pure function of the
    tree — safe to run in grade/recon and to re-run for regression."""
    app_root = Path(app_root)
    stk = classify(app_root)
    perms, deeplinks, exported, package = _parse_manifest(app_root)
    endpoints, sdks, secrets, defenses = _scan_tree(app_root, package.replace(".", "/"), stk.name)

    # Flutter/RN: the real endpoints live in the logic blob, not smali. Merge them
    # in at high confidence (they win the tie-break over any low-conf glue sighting).
    def_by_kind: dict[str, dict] = {d["kind"]: d for d in defenses}
    if stk.name in NON_SMALI_STACKS and stk.logic_blobs:
        blob_eps, blob_secrets, blob_defenses = _scan_logic_blobs(app_root, stk.logic_blobs)
        for ep in blob_eps.values():
            _add_endpoint(endpoints, ep)
        for s in blob_secrets:
            if not any(s["kind"] == e["kind"] and s["where"] == e["where"] for e in secrets):
                secrets.append(s)
        for d in blob_defenses:
            def_by_kind.setdefault(d["kind"], d)

    eps = sorted(endpoints.values(), key=lambda e: (e.host, e.scheme, e.path or ""))

    # hosts = the CLEAN server surface: high-confidence, non-telemetry endpoint
    # authorities + App Link (http/https) deeplink hosts. Low-confidence (resource /
    # glue) and known-telemetry hosts are kept out so the server-side bridge isn't
    # handed library noise as targets. A custom-scheme deeplink authority is not a
    # server host — it stays in `deeplinks`.
    applink_hosts = [d.split("://", 1)[1] for d in deeplinks
                     if d.startswith(("http://", "https://")) and d.split("://", 1)[1]]
    hosts = _dedup([e.host for e in eps if e.confidence == "high" and not _is_telemetry(e.host)]
                   + [h for h in applink_hosts if not _is_telemetry(h)])
    telemetry_hosts = _dedup([e.host for e in eps if _is_telemetry(e.host)]
                             + [h for h in applink_hosts if _is_telemetry(h)])

    return TargetIntel(
        endpoints=eps,
        hosts=hosts,
        telemetry_hosts=telemetry_hosts,
        sdks=sdks,
        permissions=perms,
        deeplinks=deeplinks,
        exported_surface=exported,
        # sorted for cross-machine determinism (assembly order follows rglob).
        secrets_observed=sorted(secrets, key=lambda s: (s["kind"], s["where"])),
        stack=stk.name,
        native_libs=_native_libs(app_root),
        signing=_signing(app_root),
        defenses=sorted(def_by_kind.values(), key=lambda d: d["kind"]),
    )
