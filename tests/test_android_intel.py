# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""Tests for harness/android_app/intel.py — the TargetIntel harvester, over the
android-canary synthetic fixture."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.android_app import intel as I

FIXTURE = Path(__file__).resolve().parents[1] / "targets" / "android-canary" / "app"


@pytest.fixture(scope="module")
def ti():
    return I.harvest(FIXTURE)


def test_endpoints_extracted(ti):
    hosts = {e.host for e in ti.endpoints}
    assert "api.canary.example" in hosts
    assert "legacy.canary.example" in hosts
    api = next(e for e in ti.endpoints if e.host == "api.canary.example")
    assert api.scheme == "https" and api.cleartext is False and api.path == "/v1/sync"
    legacy = next(e for e in ti.endpoints if e.host == "legacy.canary.example")
    assert legacy.scheme == "http" and legacy.cleartext is True


def test_xml_namespace_host_is_filtered(ti):
    # The manifest xmlns URI (http://schemas.android.com/...) must NOT be an endpoint.
    assert all(e.host != "schemas.android.com" for e in ti.endpoints)
    assert "schemas.android.com" not in ti.hosts


def test_hosts_deduped_and_clean(ti):
    assert set(ti.hosts) == {"api.canary.example", "legacy.canary.example"}


def test_sdks(ti):
    assert any(s["name"] == "OkHttp" for s in ti.sdks)


def test_permissions_and_deeplinks(ti):
    assert "android.permission.INTERNET" in ti.permissions
    assert "canary://" in ti.deeplinks


def test_exported_surface(ti):
    by_name = {c["component"]: c for c in ti.exported_surface}
    assert by_name[".ExportedForwardActivity"]["permission"] is None
    assert by_name[".GuardedForwardActivity"]["permission"] == "com.canary.app.permission.PRIVILEGED"


def test_secret_observed_but_never_stored(ti):
    assert any(s["kind"] == "google_api_key" and s["where"].endswith("strings.xml")
               and s["redacted"] is True for s in ti.secrets_observed)
    # SECURITY: the actual key value must not appear anywhere in the artifact.
    blob = json.dumps(ti.to_dict())
    assert "AIzaSyFAKEcanarykey" not in blob


def test_to_dict_is_json_serializable(ti):
    json.dumps(ti.to_dict())  # must not raise


def test_harvest_missing_tree_is_empty_not_crash(tmp_path):
    empty = I.harvest(tmp_path)
    assert empty.endpoints == [] and empty.permissions == [] and empty.exported_surface == []


def test_endpoints_scoped_to_app_package_not_bundled_sdks(tmp_path):
    # A real APK bundles SDKs (ads/analytics) whose smali carries their own URLs.
    # Those must NOT pollute the app's server-surface intel — only the app's own
    # package is scanned for endpoints (the InsecureBankv2 lesson: 55 SDK URLs → 0).
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.myapp"><application/></manifest>')
    app = tmp_path / "smali" / "com" / "myapp"
    app.mkdir(parents=True)
    (app / "Api.smali").write_text('const-string v0, "https://api.myapp.com/v1"')
    sdk = tmp_path / "smali" / "com" / "google" / "android" / "gms"
    sdk.mkdir(parents=True)
    (sdk / "Ads.smali").write_text('const-string v0, "https://googleads.g.doubleclick.net/x"')
    ti = I.harvest(tmp_path)
    hosts = {e.host for e in ti.endpoints}
    assert "api.myapp.com" in hosts
    assert "googleads.g.doubleclick.net" not in hosts  # bundled SDK, excluded
    assert any(s["name"] == "Google Play Services" for s in ti.sdks)  # but SDK still inventoried


# ── P2: host confidence + telemetry split ─────────────────────────────────────
def test_canary_endpoints_are_high_confidence_app_smali(ti):
    for e in ti.endpoints:
        assert e.confidence == "high" and e.source == "app-smali"


def test_stack_is_native_smali_for_canary(ti):
    assert ti.stack == "native-smali"


def test_telemetry_hosts_kept_out_of_clean_hosts(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.myapp"><application/></manifest>')
    app = tmp_path / "smali" / "com" / "myapp"
    app.mkdir(parents=True)
    (app / "Api.smali").write_text(
        'const-string v0, "https://api.myapp.com/v1"\n'
        'const-string v1, "https://t.appsflyer.com/track"\n'
        'const-string v2, "https://x.sentry.io/ingest"')
    ti = I.harvest(tmp_path)
    assert "api.myapp.com" in ti.hosts
    assert "t.appsflyer.com" not in ti.hosts and "t.appsflyer.com" in ti.telemetry_hosts
    assert "x.sentry.io" not in ti.hosts and "x.sentry.io" in ti.telemetry_hosts


# ── P1: Flutter branch ────────────────────────────────────────────────────────
def _flutter_tree(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="ru.x.y"><application/></manifest>')
    lib = tmp_path / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libflutter.so").write_bytes(b"\x7fELF libflutter")
    (lib / "libapp.so").write_bytes(
        b"\x00\x00https://api.example.test/api/v1 pad\x00\x00"
        b"https://t.appsflyer.com/x\x00-----BEGIN PRIVATE KEY-----\x00")
    sm = tmp_path / "smali" / "ru" / "x" / "y"
    sm.mkdir(parents=True)
    (sm / "Glue.smali").write_text('const-string v0, "https://io.flutter.plugin/noise"')
    return tmp_path


def test_flutter_real_backend_from_libapp_not_smali_glue(tmp_path):
    ti = I.harvest(_flutter_tree(tmp_path))
    assert ti.stack == "flutter"
    # the real Dart backend is the clean host; the smali glue URL is demoted out
    assert ti.hosts == ["api.example.test"]
    by_host = {e.host: e for e in ti.endpoints}
    assert by_host["api.example.test"].confidence == "high"
    assert by_host["api.example.test"].source == "libapp.so"
    assert by_host["io.flutter.plugin"].confidence == "low"          # glue, demoted
    assert by_host["io.flutter.plugin"].source == "flutter-glue"
    assert "t.appsflyer.com" in ti.telemetry_hosts                   # telemetry split


def test_flutter_secret_extracted_from_libapp_but_not_stored(tmp_path):
    ti = I.harvest(_flutter_tree(tmp_path))
    assert any(s["kind"] == "private_key_block" and s["where"].endswith("libapp.so")
               for s in ti.secrets_observed)
    assert "BEGIN PRIVATE KEY" not in json.dumps(ti.to_dict())       # kind+loc only


# ── P3: breadth (native libs / signing / defenses / sdk scope) ────────────────
def test_native_libs_inventory_with_abi(tmp_path):
    ti = I.harvest(_flutter_tree(tmp_path))
    names = {(n["name"], n["abi"]) for n in ti.native_libs}
    assert ("libapp.so", "arm64-v8a") in names
    assert ("libflutter.so", "arm64-v8a") in names


def test_signing_not_determinable_without_metainf(ti):
    assert ti.signing.get("determinable") is False


def test_signing_v1_detected_from_metainf(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.myapp"><application/></manifest>')
    mi = tmp_path / "original" / "META-INF"
    mi.mkdir(parents=True)
    (mi / "CERT.RSA").write_bytes(b"\x30\x82fake-pkcs7")
    (mi / "CERT.SF").write_text("Signature-Version: 1.0")
    ti = I.harvest(tmp_path)
    assert ti.signing["determinable"] is True and ti.signing["v1_jar_signature"] is True


def test_defenses_no_false_positive_on_canary_comments(ti):
    # Regression guard that the canary stays defense-CLEAN despite its teaching
    # comments mentioning "Frida" — those bare words never match the code-shaped
    # regex. (The actual _strip_smali_comments behaviour is covered by
    # test_defense_marker_in_smali_comment_suppressed_but_in_code_detected.)
    assert ti.defenses == []


def test_defenses_detects_real_frida_marker(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.myapp"><application/></manifest>')
    app = tmp_path / "smali" / "com" / "myapp"
    app.mkdir(parents=True)
    (app / "Rasp.smali").write_text('const-string v0, "re.frida.server"')
    ti = I.harvest(tmp_path)
    assert any(d["kind"] == "frida_detection" for d in ti.defenses)


def test_defense_marker_in_smali_comment_suppressed_but_in_code_detected(tmp_path):
    # Directly exercises _strip_smali_comments: a CODE-SHAPED marker token inside a
    # `#` comment must NOT count as a control, but the same token in a code line
    # MUST. (The canary test above can't cover this — its "Frida" prose never
    # matches the code-shaped regex whether stripped or not.)
    manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                'package="com.myapp"><application/></manifest>')
    (tmp_path / "AndroidManifest.xml").write_text(manifest)
    app = tmp_path / "smali" / "com" / "myapp"
    app.mkdir(parents=True)
    (app / "CommentOnly.smali").write_text("    # note: re.frida.server is checked elsewhere\n")
    assert not any(d["kind"] == "frida_detection" for d in I.harvest(tmp_path).defenses)
    # same token, now in a real const-string → detected
    (app / "RealCheck.smali").write_text('const-string v0, "re.frida.server"\n')
    assert any(d["kind"] == "frida_detection" for d in I.harvest(tmp_path).defenses)


def test_sdk_key_scope_annotated(tmp_path):
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.myapp"><application/></manifest>')
    fb = tmp_path / "smali" / "com" / "google" / "firebase"
    fb.mkdir(parents=True)
    (fb / "FirebaseApp.smali").write_text("# firebase")
    ti = I.harvest(tmp_path)
    fbe = next(s for s in ti.sdks if s["name"] == "Firebase")
    assert "PUBLIC client key" in fbe.get("key_scope", "")


# ── correctness-review fixes (D1/D2/D5/D6) ────────────────────────────────────
def test_harvest_survives_unusable_manifest(tmp_path):
    # D1: a directory named AndroidManifest.xml (an OSError on parse) must not
    # crash harvest() — the contract is "never hard-fails".
    (tmp_path / "AndroidManifest.xml").mkdir()
    ti = I.harvest(tmp_path)  # must not raise
    assert ti.permissions == [] and ti.exported_surface == []


def test_native_resource_only_backend_reaches_hosts(tmp_path):
    # D2: a native app whose backend lives ONLY in res/values/strings.xml (idiomatic
    # under R8, where smali keeps just the resource id) must surface in `hosts`.
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="com.acme.app"><application/></manifest>')
    res = tmp_path / "res" / "values"
    res.mkdir(parents=True)
    (res / "strings.xml").write_text(
        '<resources><string name="base_url">https://api.acme-prod.example/v2</string></resources>')
    ti = I.harvest(tmp_path)
    assert "api.acme-prod.example" in ti.hosts
    ep = next(e for e in ti.endpoints if e.host == "api.acme-prod.example")
    assert ep.confidence == "high" and ep.source == "resource"


def test_flutter_resource_url_stays_low_confidence(tmp_path):
    # D2 complement: on Flutter, resources are bundled-framework noise → low, NOT
    # promoted into hosts (the real endpoints come from libapp.so).
    t = _flutter_tree(tmp_path)
    res = t / "res" / "values"
    res.mkdir(parents=True)
    (res / "strings.xml").write_text(
        '<resources><string name="x">https://libnoise.example/asset</string></resources>')
    ti = I.harvest(t)
    assert "libnoise.example" not in ti.hosts
    assert next(e for e in ti.endpoints if e.host == "libnoise.example").confidence == "low"


def test_flutter_utf16_url_in_libapp_is_found(tmp_path):
    # D5: a TwoByteString (UTF-16LE) URL in the Dart snapshot must still be found.
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="ru.x.y"><application/></manifest>')
    lib = tmp_path / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libflutter.so").write_bytes(b"ELF")
    (lib / "libapp.so").write_bytes(
        b"\x00" + "https://utf16-backend.example/api".encode("utf-16-le") + b"\x00")
    assert "utf16-backend.example" in I.harvest(tmp_path).hosts


def test_flutter_libflutter_only_does_not_surface_engine_hosts(tmp_path):
    # D6: no libapp.so → the engine .so is NOT scanned as a logic blob, so engine
    # boilerplate (dartlang.org, …) never becomes a fake app backend.
    (tmp_path / "AndroidManifest.xml").write_text(
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="ru.x.y"><application/></manifest>')
    lib = tmp_path / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libflutter.so").write_bytes(
        b"\x00https://dartlang.org/x\x00https://api.engine.example/y\x00")
    ti = I.harvest(tmp_path)
    assert ti.stack == "flutter" and ti.hosts == []
