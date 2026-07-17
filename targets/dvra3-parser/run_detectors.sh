#!/usr/bin/env bash
set -u
BIN=/work/riptarget; SRC=/work/parser
run_one() {
  local f="$1" rc
  timeout 25 "$BIN" "$f" >/tmp/o 2>&1; rc=$?
  if [ $rc -ge 101 ] || [ $rc -eq 134 ] || [ $rc -eq 124 ]; then echo "CRASH rc=$rc $f"; sed -n '1,20p' /tmp/o; return 1; fi
  return 0
}
if [ $# -ge 1 ]; then run_one "$1"; exit $?; fi
rc=0; for f in /poc/*; do [ -e "$f" ] || continue; run_one "$f" || rc=1; done; exit $rc
