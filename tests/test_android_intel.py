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
