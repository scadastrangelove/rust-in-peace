# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Android runtime-stack classifier — which framework compiled the app.

The android-app profile's static layer reads Dalvik **smali**. That is the whole
app only for a *native* (Java/Kotlin) app. Cross-platform frameworks compile the
business logic into a bundled ``.so`` (or a JS / .NET blob) and leave smali as
thin glue — so a smali/resource scan is **blind** on them, and worse, it reports
the bundled framework's *resource* strings as if they were the app's own server
surface (the "library-resource-strings become fake endpoints" failure mode).

``classify()`` is a pure, deterministic function of the decoded APK tree (file
presence only — no tool calls, no byte parsing) that tells the recon step which
extractor to trust:

    native-smali   real logic in smali — the profile's default, fully covered
    flutter        Dart AOT in libapp.so (+ libflutter.so) — needs Dart extraction
    react-native   JS in assets/index.android.bundle (+ libhermes / libjsc)
    xamarin        .NET in assemblies/*.dll (+ libmonodroid.so)
    unity          IL2CPP in libil2cpp.so (+ assets/bin/Data)
    cordova        web app in assets/www (+ cordova.js)
    unknown        no decisive signal (treat like native-smali, but say so)

Only ``native-smali`` is fully served by the smali walk. For every other value
``intel.harvest`` suppresses smali/resource hosts (glue + library noise) and, for
``flutter``, extracts the real endpoints/secrets from the logic blob instead.
``logic_blobs`` is the list of rel paths a deeper extractor (strings / Blutter /
reFlutter for Flutter; the JS bundle for RN) should target.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Stack:
    name: str                       # native-smali | flutter | react-native | …
    evidence: list[str]             # decoded-tree rel paths that decided it
    logic_blobs: list[str]          # rel paths to the real-logic artifact(s)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except ValueError:
        return p.name


def _so_names(app_root: Path) -> dict[str, list[Path]]:
    """basename(lower) -> [paths] for every lib/**/*.so (across all ABIs)."""
    out: dict[str, list[Path]] = {}
    for p in app_root.rglob("*.so"):
        if p.is_file():
            out.setdefault(p.name.lower(), []).append(p)
    return out


def classify(app_root: str | Path) -> Stack:
    """Classify the app's runtime stack from its decoded tree. Precedence is by
    signal specificity; native-smali is the default when nothing else matches."""
    app_root = Path(app_root)
    so = _so_names(app_root)

    def has_so(name: str) -> list[str]:
        return sorted(_rel(p, app_root) for p in so.get(name, []))  # deterministic

    def exists(*relparts: str) -> str | None:
        p = app_root.joinpath(*relparts)
        return _rel(p, app_root) if p.exists() else None

    def any_glob(pattern: str) -> list[str]:
        return sorted(_rel(p, app_root) for p in app_root.glob(pattern) if p.is_file())

    # ── Flutter: libflutter.so is definitive; libapp.so is the Dart AOT blob ──
    flutter_ev = has_so("libflutter.so")
    libapp = has_so("libapp.so")
    flutter_assets = exists("assets", "flutter_assets")
    if flutter_ev or libapp or flutter_assets:
        ev = flutter_ev + libapp + ([flutter_assets] if flutter_assets else [])
        # logic blob = the app's Dart AOT snapshot (libapp.so) ONLY. We deliberately
        # do NOT fall back to libflutter.so (the ENGINE): extracting strings from the
        # engine surfaces its own boilerplate (dartlang.org, …) as fake app endpoints.
        # A split-less build with no libapp.so ⇒ no cheap blob; hunt it with Blutter.
        return Stack("flutter", ev, libapp)

    # ── React Native: the JS bundle is the logic; hermes/jsc are the engine ──
    rn_engine = has_so("libhermes.so") + has_so("libjsc.so") + has_so("libreactnativejni.so")
    rn_bundle = exists("assets", "index.android.bundle")
    if rn_bundle or rn_engine:
        ev = ([rn_bundle] if rn_bundle else []) + rn_engine
        # logic blob = the JS bundle ONLY, never the engine .so (same reason as above).
        blobs = [rn_bundle] if rn_bundle else []
        return Stack("react-native", ev, blobs)

    # ── Xamarin / .NET MAUI: mono runtime + managed assemblies ──
    xam_rt = has_so("libmonodroid.so") + has_so("libmonosgen-2.0.so") + has_so("libxamarin-app.so")
    xam_asm = any_glob("assemblies/*.dll") or any_glob("assemblies/**/*.dll")
    if xam_rt or xam_asm:
        return Stack("xamarin", xam_rt + xam_asm[:3], xam_asm[:8] or xam_rt)

    # ── Unity (IL2CPP or Mono): il2cpp/unity .so, or the tell-tale assets/bin/Data ──
    unity_rt = has_so("libil2cpp.so") + has_so("libunity.so")
    unity_meta = exists("assets", "bin", "Data")
    if unity_rt or unity_meta:
        return Stack("unity", unity_rt + ([unity_meta] if unity_meta else []),
                     has_so("libil2cpp.so"))

    # ── Cordova / Ionic: a web app under assets/www ──
    cordova = exists("assets", "www", "cordova.js") or exists("assets", "www", "index.html")
    if cordova:
        return Stack("cordova", [cordova], [cordova])

    # ── default: a native Java/Kotlin app — smali IS the logic ──
    return Stack("native-smali", [], [])


# Stacks whose real logic is NOT in smali — the smali/resource host scan is
# blind/noisy on these and must be down-ranked (see intel.harvest).
NON_SMALI_STACKS: frozenset[str] = frozenset(
    {"flutter", "react-native", "xamarin", "unity", "cordova"}
)
