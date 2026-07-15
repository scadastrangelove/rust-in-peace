#!/usr/bin/env bash
# Multi-detector run harness for the Rust-security profile.
#
#   run_detectors.sh <input_file>          — run one input under every oracle
#   run_detectors.sh                       — run every /poc/* (re-attack mode)
#
# Oracles, fast → thorough:
#   1. AddressSanitizer + panic driver  (/work/entry)   — OOB in unsafe, panics
#   2. hang timeout                                       — unbounded loop/recursion
#   3. Miri                                               — UB the sanitizer misses
#
# Exit 1 + trace on the FIRST crash; 0 if all clean; 2 on launch/setup failure.
# A `reject:` line from the driver is graceful error handling, NOT a crash.
set -o pipefail

run_one() {
    local input="$1"
    [ -f "$input" ] || { echo "no such input: $input"; return 2; }

    # 1. Sanitizer + panic driver (fast).
    local out rc
    out=$(ASAN_OPTIONS=detect_leaks=0 /work/entry "$input" 2>&1); rc=$?
    if [ $rc -ne 0 ] && ! grep -q '^reject:' <<<"$out"; then
        echo "$out"
        echo "== detector: sanitizer/panic driver (rc=$rc) =="
        return 1
    fi

    # 2. Hang: bound the driver; 124 == timed out.
    timeout 5 /work/entry "$input" >/dev/null 2>&1
    if [ $? -eq 124 ]; then
        echo "HANG: /work/entry exceeded 5s on $input (unbounded loop/recursion)"
        echo "== detector: hang-timeout =="
        return 1
    fi

    # 3. Miri (UB in unsafe: bad provenance, uninit, invalid value). Slower;
    #    needs isolation off to read the input file. Best-effort — a Miri
    #    build/setup failure is NOT a target bug (exit 2 semantics upstream).
    out=$(cd /work/crate && \
          MIRIFLAGS="-Zmiri-disable-isolation" \
          timeout 180 cargo +nightly miri run --quiet --bin entry -- "$input" 2>&1)
    if grep -q 'error: Undefined Behavior' <<<"$out"; then
        echo "$out"
        echo "== detector: miri UB =="
        return 1
    fi

    return 0
}

# Re-attack mode: no arg → sweep every /poc/*.
if [ $# -eq 0 ]; then
    shopt -s nullglob
    found=0
    for f in /poc/*; do
        [ -f "$f" ] || continue
        found=1
        if ! run_one "$f"; then
            rc=$?
            [ $rc -eq 2 ] && exit 2
            echo "(crash on $f)"
            exit 1
        fi
    done
    [ $found -eq 0 ] && { echo "no PoCs under /poc/"; exit 2; }
    echo "all clean"
    exit 0
fi

run_one "$1"
exit $?
