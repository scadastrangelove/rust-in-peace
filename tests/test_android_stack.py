# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/android_app/stack.py — the runtime-stack classifier that
decides whether the smali walk sees the real logic (native) or only glue
(Flutter / React-Native / Xamarin / Unity / Cordova)."""
from __future__ import annotations

from pathlib import Path

import pytest

from harness.android_app import stack as S

FIXTURE = Path(__file__).resolve().parents[1] / "targets" / "android-canary" / "app"


def _mkso(root: Path, abi: str, name: str) -> None:
    d = root / "lib" / abi
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(b"\x7fELF" + name.encode())


def test_canary_is_native_smali():
    st = S.classify(FIXTURE)
    assert st.name == "native-smali"
    assert st.logic_blobs == []


def test_empty_tree_is_native_smali(tmp_path):
    assert S.classify(tmp_path).name == "native-smali"


def test_flutter_via_libflutter_and_libapp(tmp_path):
    _mkso(tmp_path, "arm64-v8a", "libflutter.so")
    _mkso(tmp_path, "arm64-v8a", "libapp.so")
    st = S.classify(tmp_path)
    assert st.name == "flutter"
    assert "lib/arm64-v8a/libapp.so" in st.logic_blobs  # the Dart AOT blob


def test_flutter_via_flutter_assets_only(tmp_path):
    (tmp_path / "assets" / "flutter_assets").mkdir(parents=True)
    assert S.classify(tmp_path).name == "flutter"


def test_react_native_via_bundle(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "index.android.bundle").write_text("var x=1")
    st = S.classify(tmp_path)
    assert st.name == "react-native"
    assert "assets/index.android.bundle" in st.logic_blobs


def test_react_native_via_hermes(tmp_path):
    _mkso(tmp_path, "arm64-v8a", "libhermes.so")
    assert S.classify(tmp_path).name == "react-native"


def test_xamarin_via_monodroid(tmp_path):
    _mkso(tmp_path, "arm64-v8a", "libmonodroid.so")
    assert S.classify(tmp_path).name == "xamarin"


def test_unity_via_il2cpp(tmp_path):
    _mkso(tmp_path, "arm64-v8a", "libil2cpp.so")
    assert S.classify(tmp_path).name == "unity"


def test_cordova_via_www(tmp_path):
    (tmp_path / "assets" / "www").mkdir(parents=True)
    (tmp_path / "assets" / "www" / "cordova.js").write_text("//cordova")
    assert S.classify(tmp_path).name == "cordova"


def test_flutter_precedence_over_bundled_hermes(tmp_path):
    # A Flutter app can still bundle other engines; libflutter.so must win.
    _mkso(tmp_path, "arm64-v8a", "libflutter.so")
    _mkso(tmp_path, "arm64-v8a", "libapp.so")
    _mkso(tmp_path, "arm64-v8a", "libhermes.so")
    assert S.classify(tmp_path).name == "flutter"


def test_non_smali_stacks_membership():
    assert "flutter" in S.NON_SMALI_STACKS
    assert "native-smali" not in S.NON_SMALI_STACKS
