# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""TargetIntel — the non-vulnerability intelligence the android-app walk surfaces.

Distinct from a *finding* (a vulnerability witness): this is an inventory of the
app's outward shape — the server endpoints / hosts it talks to, the third-party
SDKs it bundles, the permissions it requests, its deep-link schemes, its exported-
component surface, and secrets *observed* (recorded by kind + location, **never**
stored). A C parser has none of this; an app does, which is why the android-app
profile is where the pipeline grows a first-class intelligence artifact alongside
its findings.

The **endpoints / hosts** list is the payload that bridges to server-side testing:
the mobile client enumerates the API hosts that a downstream EASM / DAST / passive-
DNS pipeline then attacks. The app is a discovery vector for the server surface.

`harvest()` is a deterministic scan over a decoded APK tree (AndroidManifest.xml +
smali/) — the canary runs it directly; a real target's recon step runs the same
harvester over apktool/jadx output. It is emitted as `intel.json` next to a run's
results.

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

_ANDROID = "{http://schemas.android.com/apk/res/android}"


# ── data model ───────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Endpoint:
    host: str
    scheme: str                 # https | http | ws | wss | ftp …
    path: str | None            # first path seen, if any
    cleartext: bool             # scheme is a plaintext transport
    evidence: str               # where it was found

    def key(self) -> tuple[str, str, str | None]:
        return (self.scheme, self.host, self.path)


@dataclass(frozen=True)
class TargetIntel:
    endpoints: list[Endpoint] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)              # distinct, derived
    sdks: list[dict] = field(default_factory=list)              # {name, evidence}
    permissions: list[str] = field(default_factory=list)
    deeplinks: list[str] = field(default_factory=list)          # scheme:// or scheme://host
    exported_surface: list[dict] = field(default_factory=list)  # {component, type, permission|None}
    secrets_observed: list[dict] = field(default_factory=list)  # {kind, where, redacted: true}

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
})

# Known SDK/library package prefixes → display name. Extend as the corpus grows.
_SDK_PREFIXES: list[tuple[str, str]] = [
    ("com/google/firebase", "Firebase"),
    ("com/google/android/gms", "Google Play Services"),
    ("com/facebook", "Facebook SDK"),
    ("com/squareup/okhttp", "OkHttp"),
    ("okhttp3", "OkHttp"),
    ("retrofit2", "Retrofit"),
    ("com/amplitude", "Amplitude"),
    ("com/mixpanel", "Mixpanel"),
    ("io/sentry", "Sentry"),
    ("com/crashlytics", "Crashlytics"),
    ("com/appsflyer", "AppsFlyer"),
    ("com/adjust/sdk", "Adjust"),
    ("com/stripe", "Stripe"),
]

# Secret shapes. (label, compiled pattern) — matched against smali + resources.
# We record kind + location only; the value is NEVER stored.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("bearer_or_jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("generic_api_key_assignment",
     re.compile(r"""(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)"""
                r"""["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{12,}["']""")),
]


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


# ── manifest ─────────────────────────────────────────────────────────────────
def _parse_manifest(app_root: Path) -> tuple[list[str], list[str], list[dict]]:
    """(permissions, deeplinks, exported_surface) from AndroidManifest.xml.
    Missing/unparsable manifest → empty lists (the harvester never hard-fails)."""
    mf = app_root / "AndroidManifest.xml"
    if not mf.exists():
        return [], [], []
    try:
        root = ET.parse(mf).getroot()
    except ET.ParseError:
        return [], [], []

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
    return perms, deeplinks, exported


# ── smali / resources scan ───────────────────────────────────────────────────
def _scan_tree(app_root: Path) -> tuple[list[Endpoint], list[dict], list[dict]]:
    """(endpoints, sdks, secrets_observed) from smali + resource text files."""
    endpoints: dict[tuple, Endpoint] = {}
    sdk_hits: dict[str, str] = {}
    secrets: list[dict] = []
    secret_seen: set[tuple[str, str]] = set()

    text_files = [p for p in app_root.rglob("*")
                  if p.is_file() and p.suffix in (".smali", ".xml", ".json", ".properties", ".txt")]

    for p in text_files:
        rel = _rel(p, app_root)
        try:
            body = p.read_text(errors="replace")
        except OSError:
            continue

        for m in _URL.finditer(body):
            scheme, host, path = m.group(1), m.group(2), m.group(3)
            if host in _NOISE_HOSTS:
                continue
            ep = Endpoint(host=host, scheme=scheme, path=path,
                          cleartext=scheme in _CLEARTEXT_SCHEMES, evidence=rel)
            endpoints.setdefault(ep.key(), ep)

        for kind, pat in _SECRET_PATTERNS:
            if pat.search(body) and (kind, rel) not in secret_seen:
                secret_seen.add((kind, rel))
                secrets.append({"kind": kind, "where": rel, "redacted": True})

    # SDKs: match package prefixes against smali *paths* (structural, low-noise).
    for p in app_root.rglob("*.smali"):
        rel = _rel(p, app_root).replace("\\", "/")
        for prefix, name in _SDK_PREFIXES:
            if f"/{prefix}" in f"/{rel}" and name not in sdk_hits:
                sdk_hits[name] = rel

    eps = sorted(endpoints.values(), key=lambda e: (e.host, e.scheme, e.path or ""))
    sdks = [{"name": n, "evidence": ev} for n, ev in sorted(sdk_hits.items())]
    return eps, sdks, secrets


# ── entry point ──────────────────────────────────────────────────────────────
def harvest(app_root: str | Path) -> TargetIntel:
    """Deterministically harvest TargetIntel from a decoded APK tree
    (`app_root` contains AndroidManifest.xml and smali/). Pure function of the
    tree — safe to run in grade/recon and to re-run for regression."""
    app_root = Path(app_root)
    perms, deeplinks, exported = _parse_manifest(app_root)
    endpoints, sdks, secrets = _scan_tree(app_root)

    hosts = _dedup([e.host for e in endpoints]
                   + [d.split("://", 1)[1] for d in deeplinks if "://" in d and d.split("://", 1)[1]])

    return TargetIntel(
        endpoints=endpoints,
        hosts=hosts,
        sdks=sdks,
        permissions=perms,
        deeplinks=deeplinks,
        exported_surface=exported,
        secrets_observed=secrets,
    )
