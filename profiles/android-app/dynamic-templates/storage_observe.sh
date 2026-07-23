#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# storage_observe.sh — promote an insecure-storage finding by OBSERVING the secret
# sitting in cleartext at rest.
#   plan:       adb_storage_observe         (find_to_fuzz.py _PLAN_PLAYBOOK)
#   capability: insecure_storage            (android:insecure-storage-secret)
#   tier:       A (light_adb), domain=storage — earns strength 2.
#
# What it promotes: a strength-1 static argument "the app writes <secret> to
# SharedPreferences/SQLite/a file without encryption" into a strength-2
# dynamic_observation — by DRIVING the flow that writes the secret (login / token
# refresh), then reading the file back as the app (`run-as`, debuggable) or via
# `adb backup` and CONFIRMING the datum is present unencrypted.
#
# The witness is the cleartext datum on disk, not that a write happened. If the
# field is stored ENCRYPTED (EncryptedSharedPreferences / Keystore-wrapped), the
# secret is protected → GUARD_BLOCKED=true → path REFUTED (guard_held), a
# correctness WIN — reported honestly. If the store cannot be read at all on this
# device/tier (not debuggable AND allowBackup=false), that is *not* guard_held —
# it is contested (Tier A can't observe; escalate to a rooted/instrumented run).
set -u

# ─────────────────────────── <PLACEHOLDERS> ───────────────────────────────────
PKG="<pkg>"                         # e.g. com.example.app
# The command that DRIVES the write (login / token refresh). Use am/monkey/input;
# adapt to the app. Must run the code path the finding says writes the secret.
DRIVE_CMD='adb shell am start -n <pkg>/<login_component> -a <action> --es user demo --es pass demo'
STORE_REL="shared_prefs/<prefs_file>.xml"   # path under /data/data/<pkg>/ that holds the secret
SECRET_KEY="<secret_key>"          # the prefs key / column name the secret is stored under
# A regex matching the secret IN CLEARTEXT (a token prefix, a PAN, an API-key shape).
# Match the value form, not the key, so ciphertext under the same key does NOT hit.
SECRET_RE="<secret_regex>"         # e.g. eyJ[A-Za-z0-9_-]{20,}|sk_live_[0-9a-zA-Z]{16,}
# ───────────────────────────────────────────────────────────────────────────────

ATTEMPTS=3
STORE_ABS="/data/data/${PKG}/${STORE_REL}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

if ! adb get-state >/dev/null 2>&1; then
  printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
  printf 'EFFECT_OBSERVED=false\nRUNS=0\nOF_RUNS=0\nGUARD_BLOCKED=false\nDEVICE_AVAILABLE=false\nEVIDENCE=no adb device/emulator\n'
  exit 0
fi

# Read the store back. Primary: run-as (works iff the app is debuggable). Fallback:
# adb backup (works iff allowBackup=true; on an emulator auto-confirm the on-screen
# dialog). Prints the file content on stdout, or nothing if unreadable on this tier.
read_store() {
  c="$(adb shell run-as "$PKG" cat "$STORE_ABS" 2>/dev/null)"
  if [ -n "$c" ]; then printf '%s' "$c"; return 0; fi
  # fallback: adb backup → skip 24-byte header, zlib-inflate, untar, read the file
  adb backup -f "$WORK/b.ab" -noapk "$PKG" >/dev/null 2>&1 || return 1
  python3 - "$WORK/b.ab" "$WORK/b.tar" <<'PY' 2>/dev/null || return 1
import sys, zlib
raw = open(sys.argv[1], "rb").read()
open(sys.argv[2], "wb").write(zlib.decompress(raw[24:]))   # 24-byte "ANDROID BACKUP" header
PY
  tar -xf "$WORK/b.tar" -C "$WORK" 2>/dev/null || return 1
  find "$WORK" -path "*${STORE_REL}" -exec cat {} \; 2>/dev/null
}

hits=0; guard=false; readable_any=false; evidence=""
for i in $(seq 1 "$ATTEMPTS"); do
  eval "$DRIVE_CMD" >/dev/null 2>&1     # drive the write flow
  sleep 2
  content="$(read_store)"
  [ -n "$content" ] && readable_any=true
  if printf '%s' "$content" | grep -qaiE "$SECRET_RE"; then
    hits=$((hits+1))
    evidence="cleartext at ${STORE_REL}: $(printf '%s' "$content" | grep -aiE "$SECRET_RE" | head -1 | cut -c1-120)"
  elif printf '%s' "$content" | grep -qa "$SECRET_KEY"; then
    # the key IS stored but the value is not cleartext → encrypted at rest → guard
    guard=true
    evidence="key '${SECRET_KEY}' present but value is not cleartext (encrypted at rest)"
  fi
done

# effect wins over guard: a cleartext hit on any run means the datum leaked.
effect=false; [ "$hits" -gt 0 ] && effect=true
if [ "$effect" = true ]; then guard=false; fi
# unreadable on this tier is NOT guard_held — it is contested (can't observe here).
if [ "$readable_any" = false ]; then
  guard=false
  evidence="store unreadable on Tier A (not debuggable AND allowBackup=false) — escalate, not guard_held"
fi

printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
printf 'EFFECT_OBSERVED=%s\nRUNS=%s\nOF_RUNS=%s\nGUARD_BLOCKED=%s\nDEVICE_AVAILABLE=true\nEVIDENCE=%s\n' \
  "$effect" "$hits" "$ATTEMPTS" "$guard" "${evidence:-none}"

# effect + 3/3   → promoted, dynamic_observation strength 2 (storage): secret at rest in cleartext
# guard_blocked  → guard_held (EncryptedSharedPreferences / Keystore-wrapped — REFUTED, correctness win)
# no read at all → contested (Tier A can't observe; escalate to rooted / instrumented)
