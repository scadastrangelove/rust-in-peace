#!/usr/bin/env bash
# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# Generalized fuzz/soak runner — the profile-agnostic reference implementation of
# the three operational lessons from the lopdf campaign (LESSONS.md L10, L-ops):
#
#   1. SHIPPING PROFILE (L10/P0.1): build the fuzz target under the target's real
#      release flags, NOT the detection build. A crash under a detection-only flag
#      (rust overflow-checks, cpp UBSan) is a build-config artifact, not a bug.
#      `harness/build_profile.py` is the source of truth for which classes are
#      instrumentation-gated; this script just refuses to *introduce* them.
#   2. DISTINCT SITES, NOT THE COUNTER (L-ops/P0.3): `-ignore_crashes` keeps a
#      repeat-hit counter (lopdf: 6911) that is NOT a finding count. On completion
#      we reproduce each saved artifact through the binary and dedup by panic
#      site via `harness/soak.py` — the SOAK-DONE line carries `distinct_sites=N`.
#   3. PERIODIC COPY-OUT + DETACH (P2.2): artifacts are copied out every interval
#      (not only at the end, so mid-run triage works), and the run is meant to be
#      launched detached (`nohup … & disown`) so a dropped SSH doesn't SIGHUP the
#      container.
#
# Usage:
#   run_fuzz_soak.sh <target> [profile] [fork_n] [seconds]
#     target   fuzz target name (a cargo-fuzz target, or an AFL/libFuzzer binary)
#     profile  rust|cpp   (selects the shipping build flags; default: rust)
#     fork_n   fork-mode parallelism (default: 4)
#     seconds  fuzz-time budget, -max_total_time (default: 21600 = 6h)
#
# Env:
#   IMAGE          docker image with the built harness (default: vuln-pipeline-$profile-fuzz:latest)
#   OUT            host output dir (default: ~/fuzz-out/<target>)
#   REPRO_BIN      path INSIDE the container to the single-input repro binary
#                  (default: cargo-fuzz layout target/*/release/<target>)
#
# This is a reference: the docker invocation mirrors the lopdf image layout
# (/work/crate copied to /tmp/w). Adapt the two `docker run` lines to a new
# image, keep the shipping-flags + site-enumeration discipline.
set -u

TGT="${1:?usage: run_fuzz_soak.sh <target> [profile] [fork_n] [seconds]}"
PROFILE="${2:-rust}"
NF="${3:-4}"
BUDGET="${4:-21600}"
IMAGE="${IMAGE:-vuln-pipeline-${PROFILE}-fuzz:latest}"
OUT="${OUT:-$HOME/fuzz-out/$TGT}"
COPY_INTERVAL="${COPY_INTERVAL:-600}"   # seconds between artifact copy-outs

mkdir -p "$OUT/corpus" "$OUT/artifacts"

# ── 1. shipping-profile RUSTFLAGS/CFLAGS (L10) ───────────────────────────────
case "$PROFILE" in
  rust) BUILD_ENV=(-e RUSTFLAGS="-Coverflow-checks=off -Cdebug-assertions=off") ;;
  cpp)  BUILD_ENV=(-e CFLAGS="-O2 -DNDEBUG" -e CXXFLAGS="-O2 -DNDEBUG") ;;
  *)    echo "unknown profile $PROFILE (want rust|cpp)"; exit 2 ;;
esac

# ── sandbox hardening (F2, self-review) ──────────────────────────────────────
# This script builds+runs UNTRUSTED target code (cargo-fuzz recompiles the crate,
# executing its build.rs/proc-macros, then runs the harness). The rest of the
# pipeline enforces gVisor via harness/docker_ops + sandbox.require; this script
# must not bypass it. Refuse to run untrusted code under plain runc unless the
# operator explicitly opts out.
RUNTIME="${VULN_PIPELINE_AGENT_RUNTIME:-runsc}"
if ! sudo docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q "\"$RUNTIME\""; then
  if [ "${VP_SOAK_NO_SANDBOX:-0}" = "1" ]; then
    echo "WARN: OCI runtime '$RUNTIME' not registered; VP_SOAK_NO_SANDBOX=1 → default runtime (UNSAFE for untrusted code)"
    RUNTIME=""
  else
    echo "ERROR: OCI runtime '$RUNTIME' (gVisor) not registered — refusing to build/run untrusted fuzz code without it." >&2
    echo "       register it (scripts/setup_sandbox.sh) or set VP_SOAK_NO_SANDBOX=1 to override." >&2
    exit 3
  fi
fi
HARDEN=(--cap-drop=ALL --security-opt=no-new-privileges --pids-limit=4096)
[ -n "$RUNTIME" ] && HARDEN+=(--runtime="$RUNTIME")

echo "=== soak $TGT profile=$PROFILE fork=$NF budget=${BUDGET}s SHIPPING build runtime=${RUNTIME:-default} ==="

# ── periodic copy-out of in-container artifacts (P2.2) ────────────────────────
# libFuzzer writes crash-<hash> into the container's artifact dir during the run;
# copy them out on an interval so a mid-run poll can enumerate sites early.
( while sudo docker ps --format '{{.Names}}' | grep -q "^fuzz_$TGT\$"; do
    sudo docker cp "fuzz_$TGT:/tmp/w/fuzz/artifacts/$TGT/." "$OUT/artifacts/" 2>/dev/null
    sleep "$COPY_INTERVAL"
  done ) &
COPY_PID=$!

# ── 2. the fuzz run itself ───────────────────────────────────────────────────
# NB: the fuzz container keeps network access — cargo-fuzz recompiles the crate
# and needs crates.io. gVisor (runsc) is the isolation for that untrusted build;
# pre-building the target into the image would let this drop to --network=none.
sudo docker run --rm --name "fuzz_$TGT" "${HARDEN[@]}" -v "$OUT":/out "${BUILD_ENV[@]}" "$IMAGE" bash -c "
    cp -r /work/crate /tmp/w && cd /tmp/w
    cp /work/crate/fuzz/corpus/$TGT/* /out/corpus/ 2>/dev/null
    cargo fuzz run $TGT /out/corpus -- -fork=$NF -ignore_crashes=1 \
        -max_total_time=$BUDGET -rss_limit_mb=4096 -timeout=25 -print_final_stats=1
    cp -rf fuzz/artifacts/$TGT/. /out/artifacts/ 2>/dev/null
  " > "$OUT/soak.log" 2>&1

kill "$COPY_PID" 2>/dev/null

# ── 3. enumerate DISTINCT SITES, not the counter (L-ops/P0.3) ────────────────
# Reproduce each saved artifact through the repro binary; hand the outputs to
# harness/soak.py, which dedups by panic site via the profile detector.
REPRO_BIN="${REPRO_BIN:-/tmp/w/fuzz/target/x86_64-unknown-linux-gnu/release/$TGT}"
OUTPUTS_DIR="$OUT/repro_outputs"; mkdir -p "$OUTPUTS_DIR"
N=0
for f in "$OUT"/artifacts/crash-* "$OUT"/artifacts/oom-* "$OUT"/artifacts/timeout-*; do
  [ -e "$f" ] || continue
  N=$((N+1))
  # repro just runs the built binary on one input — no build, no network needed.
  sudo docker run --rm "${HARDEN[@]}" --network=none -v "$OUT":/out "$IMAGE" \
      "$REPRO_BIN" "/out/artifacts/$(basename "$f")" \
      > "$OUTPUTS_DIR/$(basename "$f").out" 2>&1 || true
done

# harness/soak.py turns the reproduced outputs into a site enumeration + report.
python3 - "$TGT" "$OUTPUTS_DIR" "$N" <<'PY' >> "$OUT/soak.log"
import sys, pathlib
from harness import soak
tgt, outdir, n = sys.argv[1], pathlib.Path(sys.argv[2]), int(sys.argv[3])
outputs = [p.read_text(errors="replace") for p in sorted(outdir.glob("*.out"))]
sites = soak.enumerate_sites(outputs)
print(soak.format_site_report(sites, total_inputs=n))
print(soak.done_line(tgt, sites, n))
PY

echo "SOAK-DONE-$TGT $(date -u)" >> "$OUT/soak.log"
echo "done — see $OUT/soak.log (distinct_sites line is the finding count, not 'crash: N')"
