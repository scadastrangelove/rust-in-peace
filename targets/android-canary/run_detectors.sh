#!/usr/bin/env bash
# Reachability-oracle run harness for the android-app profile (reattack_harness).
#
#   run_detectors.sh <candidate_file>   — validate ONE candidate path
#   run_detectors.sh                     — re-attack: validate every /poc/*
#
# There is ONE oracle here: /work/reach — a deterministic re-walker over the
# decompiled fixture (AndroidManifest.xml + smali/). Unlike the cpp/rust image
# there is no sanitizer and no emulator; the "crash" is a reachability WITNESS.
# reach exits:
#     1  + a WITNESS block   -> the path holds (the finding reproduces)
#     0  + a `reject:` line   -> a guard blocks it / sink unreached (clean)
#     2                       -> setup failure (bad/missing candidate, unparsable manifest)
#
# So the re-attack semantics mirror cpp/rust exactly: a validated WITNESS is the
# analog of a persisting crash (exit 1); a `reject:` is graceful handling (exit
# 0). Determinism bar: reach is a pure function of the fixture, so 3/3 re-runs
# agree. A REAL target swaps reach's grep/parse for androguard; this contract is
# unchanged.
set -o pipefail

REACH=${REACH:-/work/reach}

run_one() {
    local cand="$1"
    [ -f "$cand" ] || { echo "no such candidate: $cand"; return 2; }

    local out rc
    out=$("$REACH" "$cand" 2>&1); rc=$?
    echo "$out"
    case $rc in
        1) echo "== oracle: reachability witness (path holds) =="; return 1 ;;
        2) echo "== oracle: setup failure =="; return 2 ;;
        *) return 0 ;;   # reject: -> guard holds / sink unreached = clean
    esac
}

# Re-attack mode: no arg -> sweep every /poc/* candidate.
if [ $# -eq 0 ]; then
    shopt -s nullglob
    found=0
    for f in /poc/*; do
        [ -f "$f" ] || continue
        found=1
        run_one "$f"; rc=$?
        [ "$rc" -eq 2 ] && exit 2
        if [ "$rc" -eq 1 ]; then
            echo "(reachable: $f)"
            exit 1
        fi
    done
    [ "$found" -eq 0 ] && { echo "no candidates under /poc/"; exit 2; }
    echo "all rejected (clean)"
    exit 0
fi

run_one "$1"
exit $?
