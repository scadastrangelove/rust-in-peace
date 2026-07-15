#!/usr/bin/env bash
# Multi-detector run harness for the russcan target.
#   run_detectors.sh <db_file>   — run one input under every oracle
#   run_detectors.sh             — run every /poc/* (re-attack mode)
# Oracles: (1) ASan+panic driver, (2) hang-timeout, (3) Miri (scalar backend —
# under Miri, is_x86_feature_detected returns false, so russcan uses V128Scalar,
# so the confirm-path unchecked reads are Miri-checkable even though the real
# SIMD path isn't). Exit 1 + trace on first crash; 0 clean; 2 on setup failure.
# A `reject:` line from the driver is graceful error handling, not a crash.
set -o pipefail

run_one() {
    local input="$1"
    [ -f "$input" ] || { echo "no such input: $input"; return 2; }

    local out rc
    out=$(ASAN_OPTIONS=detect_leaks=0 /work/riptarget "$input" 2>&1); rc=$?
    if [ $rc -ne 0 ] && ! grep -q '^reject:' <<<"$out"; then
        echo "$out"; echo "== detector: sanitizer/panic driver (rc=$rc) =="; return 1
    fi

    timeout 8 /work/riptarget "$input" >/dev/null 2>&1
    if [ $? -eq 124 ]; then
        echo "HANG: /work/riptarget exceeded 8s on $input"; echo "== detector: hang-timeout =="; return 1
    fi

    out=$(cd /work/russcan && \
          MIRIFLAGS="-Zmiri-disable-isolation" \
          timeout 300 cargo +nightly miri run --quiet -p russcan --bin riptarget -- "$input" 2>&1)
    if grep -q 'error: Undefined Behavior' <<<"$out"; then
        echo "$out"; echo "== detector: miri UB =="; return 1
    fi
    return 0
}

if [ $# -eq 0 ]; then
    shopt -s nullglob
    found=0
    for f in /poc/*; do
        [ -f "$f" ] || continue
        found=1
        if ! run_one "$f"; then
            rc=$?; [ $rc -eq 2 ] && exit 2
            echo "(crash on $f)"; exit 1
        fi
    done
    [ $found -eq 0 ] && { echo "no PoCs under /poc/"; exit 2; }
    echo "all clean"; exit 0
fi

run_one "$1"
exit $?
