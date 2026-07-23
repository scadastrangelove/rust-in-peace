#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# intent_probe.sh — promote an exported-IPC finding by OBSERVING the sink.
#   plan:       adb_intent_probe            (find_to_fuzz.py _PLAN_PLAYBOOK)
#   capability: exported_ipc  (android:exported-activity-launch / -service /
#                              broadcast-injection)
#   tier:       A (light_adb) — no instrumentation; earns strength 2.
#
# What it promotes: a strength-1 static argument "an unprivileged 3rd-party app can
# send Intent X to exported <component> and reach sink Y past guard Z" into a
# strength-2 dynamic_observation — by sending that Intent from the adb `shell` uid
# (2000, unprivileged relative to the app, i.e. a stand-in for a malicious caller)
# and watching the SINK fire in logcat / the returned broadcast result.
#
# The OBSERVED effect — not the fact that `am` returned 0 — is the witness.
# A probe the component REJECTS (Permission Denial / SecurityException / not
# exported) is GUARD_BLOCKED=true → the path is REFUTED (guard_held). That is a
# correctness WIN, reported honestly, never dressed up as an observation.
set -u

# ─────────────────────────── <PLACEHOLDERS> ───────────────────────────────────
# Fill these for THIS app (enumerate with: adb shell dumpsys package <pkg> |
# grep -A2 -iE 'Activity|Service|Receiver' , or read AndroidManifest.xml).
PKG="<pkg>"                         # e.g. com.example.app
COMPONENT="<pkg>/<component>"       # e.g. com.example.app/.ui.DeepHandlerActivity
COMPONENT_KIND="<activity|service|receiver>"
ACTION="<action>"                  # e.g. com.example.app.ACTION_LOAD  (or android.intent.action.VIEW)
EXTRA_KEY="<extra_key>"            # the attacker-controlled extra the sink reads
ATTACKER_VALUE="<attacker_value>"  # a value that makes the sink observable (a marker URL/id/path)
# A regex that appears in logcat / the broadcast result ONLY when the SINK fires.
# Tie it to the attacker value so a mere component-start doesn't false-positive.
SINK_RE="<sink_marker_regex>"      # e.g. loadUrl.*<attacker_value>|opened file <attacker_value>
# Extra am args, if the sink needs them (--ei int / --ez bool / -d <uri> / --grant-read-uri-permission)
EXTRA_ARGS=()                      # e.g. EXTRA_ARGS=(-d "content://evil/x" --ez admin true)
# ───────────────────────────────────────────────────────────────────────────────

ATTEMPTS=3                          # promote.DET_BAR — 3/3 identical or not promoted
SETTLE=2                            # seconds to let the sink emit before reading logcat
# Guard signatures: the component refusing the crafted Intent = path refuted.
DENY_RE='Permission Denial|SecurityException|not exported|requires .*permission|Abort|does not exist'

# ── device gate: no device ⇒ device_unavailable, not a clean 0-observed run ─────
if ! adb get-state >/dev/null 2>&1; then
  printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
  printf 'EFFECT_OBSERVED=false\nRUNS=0\nOF_RUNS=0\nGUARD_BLOCKED=false\nDEVICE_AVAILABLE=false\nEVIDENCE=no adb device/emulator\n'
  exit 0
fi

# ── one drive: send the crafted Intent as the unprivileged shell uid ───────────
drive() {
  # ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} = the safe empty-array expansion: it emits
  # nothing (and does not trip `set -u`) when EXTRA_ARGS is unset/empty.
  case "$COMPONENT_KIND" in
    activity) adb shell am start                  -n "$COMPONENT" -a "$ACTION" --es "$EXTRA_KEY" "$ATTACKER_VALUE" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} 2>&1 ;;
    service)  adb shell am start-foreground-service -n "$COMPONENT" -a "$ACTION" --es "$EXTRA_KEY" "$ATTACKER_VALUE" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} 2>&1 ;;
    receiver) adb shell am broadcast              -n "$COMPONENT" -a "$ACTION" --es "$EXTRA_KEY" "$ATTACKER_VALUE" ${EXTRA_ARGS[@]+"${EXTRA_ARGS[@]}"} 2>&1 ;;
    *) echo "set COMPONENT_KIND to activity|service|receiver" >&2; return 2 ;;
  esac
}

hits=0; guard=false; evidence=""
for i in $(seq 1 "$ATTEMPTS"); do
  adb logcat -c >/dev/null 2>&1
  out="$(drive)"
  # A guard that rejects the Intent REFUTES the path (correctness win). The `am`
  # result AND logcat can carry it (a caught SecurityException logs, not prints).
  if printf '%s' "$out" | grep -qiE "$DENY_RE"; then
    guard=true; evidence="$(printf '%s' "$out" | grep -iE "$DENY_RE" | head -1)"; continue
  fi
  sleep "$SETTLE"
  # OBSERVE the sink: a logcat line matching the attacker-tied marker, OR a
  # receiver that returned attacker-influenced result data (am prints
  # "Broadcast completed: result=..., data=...").
  line="$(adb logcat -d -v brief 2>/dev/null | grep -aiE "$SINK_RE" | tail -1)"
  if [ -z "$line" ]; then
    line="$(printf '%s' "$out" | grep -iE "Broadcast completed: result=.*data=.*$SINK_RE" | tail -1)"
  fi
  if [ -n "$line" ]; then hits=$((hits+1)); evidence="$line"; fi
done

# ── emit the Observation (identical-marker count is the determinism the engine
#    gates on; confirm the EVIDENCE lines really match across runs, not just that
#    3 non-empty lines appeared) ─────────────────────────────────────────────────
effect=false; [ "$hits" -gt 0 ] && effect=true
printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
printf 'EFFECT_OBSERVED=%s\nRUNS=%s\nOF_RUNS=%s\nGUARD_BLOCKED=%s\nDEVICE_AVAILABLE=true\nEVIDENCE=%s\n' \
  "$effect" "$hits" "$ATTEMPTS" "$guard" "${evidence:-none}"

# Promotion the engine will derive from the block above:
#   effect + 3/3          → promoted, dynamic_observation strength 2 (behavior)
#   guard_blocked         → guard_held (REFUTED — a correctness win, not a failure)
#   effect but RUNS<3     → contested (flaky; retry or escalate structure_gated→Tier B)
#   no effect, no guard   → contested (wants retry / heavier tier)
