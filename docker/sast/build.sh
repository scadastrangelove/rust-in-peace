#!/usr/bin/env bash
# build.sh — reproducible (re)build and VERIFICATION of the vuln-pipeline-sast image.
#
# Why this exists as code rather than a README line.
#
# The Dockerfile installs four of its six engines with `|| echo "… BUILD FAILED" >> BUILD-FAILURES.txt`
# — cargo-audit, cargo-geiger, cargo-dylint and the dylint/general prebuild all fail OPEN. The build
# then reports success with those engines absent, the note lands in a file nothing reads, and the only
# downstream trace is `engines_absent` in a per-run manifest that a human has to notice.
#
# That is not hypothetical. It is how we lost track of what the corpus was actually scanned with:
# every archived run in `results/` fired only the five `rip-e00*` ast-grep enumerators, and the
# conclusions drawn from those runs (cell precision, site-missed rates) were attributed to the method
# rather than to a five-rule pack. An engine that silently does not run is indistinguishable from an
# engine that ran and found nothing — the same defect the normalizer's "every drop is counted" rule
# exists to prevent, one layer lower.
#
# So: build, then PROVE each engine executes inside the image, and emit a machine-readable manifest
# that pins what a run may later claim. `--strict` makes the measurement set mandatory, because a
# comparison against an older run is only sound when both ran the same engines.
#
# Usage:
#   ./build.sh                 # build base + overlay, verify, write engine-manifest.json
#   ./build.sh --strict        # additionally FAIL if any measurement engine is missing
#   ./build.sh --verify-only   # no build; just verify an existing image
#   ./build.sh --overlay-only  # rebuild only the thin script layer (seconds, not ~40 min)
#   ./build.sh --with-semgrep-rules   # opt in to the licence-restricted pack (NOT distributable)
#
# Env: SAST_IMAGE (default vuln-pipeline-sast:v1), DOCKER (default docker).
set -euo pipefail

TAG="${SAST_IMAGE:-vuln-pipeline-sast:v1}"
DOCKER="${DOCKER:-docker}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRICT=0; VERIFY_ONLY=0; OVERLAY_ONLY=0; SEMGREP_RULES=0

for a in "$@"; do
  case "$a" in
    --strict)              STRICT=1 ;;
    --verify-only)         VERIFY_ONLY=1 ;;
    --overlay-only)        OVERLAY_ONLY=1 ;;
    --with-semgrep-rules)  SEMGREP_RULES=1 ;;
    -h|--help)             sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

# Engines the layer cannot function without — a missing one is always a hard failure.
CORE_ENGINES=(opengrep ast-grep clippy)
# Engines that E13-era runs used. Optional day to day; REQUIRED whenever a run will be compared to a
# previous one, because "we changed the rules" and "we dropped three engines" are not the same claim.
MEASUREMENT_ENGINES=(cargo-audit cargo-geiger cargo-dylint)

log() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$DOCKER" >/dev/null || die "no '$DOCKER' on PATH"

# ── build ────────────────────────────────────────────────────────────────────────────────────────
if [ "$VERIFY_ONLY" -eq 0 ]; then
  if [ "$OVERLAY_ONLY" -eq 0 ]; then
    log "building base image $TAG (tool layer is ~40 min of cargo installs; cached on rebuild)"
    "$DOCKER" build \
      --build-arg "INCLUDE_SEMGREP_RULES=$SEMGREP_RULES" \
      -t "$TAG" "$HERE"
  fi
  # The overlay copies the scripts last so a shell fix costs seconds instead of the whole tool layer.
  if [ -f "$HERE/Dockerfile.scripts" ]; then
    log "applying script overlay"
    "$DOCKER" build -f "$HERE/Dockerfile.scripts" -t "$TAG" "$HERE"
  fi
fi

"$DOCKER" image inspect "$TAG" >/dev/null 2>&1 || die "image $TAG does not exist — run without --verify-only"

# ── surface what the Dockerfile swallowed ────────────────────────────────────────────────────────
log "build-time failures recorded inside the image"
BUILD_FAILURES="$("$DOCKER" run --rm --entrypoint sh "$TAG" -c 'cat /opt/sast/BUILD-FAILURES.txt 2>/dev/null || true')"
if [ -n "$BUILD_FAILURES" ]; then
  printf '%s\n' "$BUILD_FAILURES" | sed 's/^/    /'
else
  echo "    (none)"
fi

# ── verify: every engine must EXECUTE, not merely exist ──────────────────────────────────────────
# `command -v` is not evidence. A dylint driver that cannot load, or a clippy without its SARIF
# bridge, both pass a which-check and produce an empty artifact at scan time — which reads as a clean
# result. Each probe below runs the engine and captures its version output.
# RUN AS THE REAL RUN DOES. sast-scan.sh's analyze phase passes `--user "$(id -u):$(id -g)"`, and the
# first version of this verifier probed as root — so it certified an image on which every OpenGrep
# pass then failed at run time with "failed to open '/.cache/opengrep/…' for writing", and a 25-crate
# corpus run produced 0 hits that read as "nothing found". Verifying under different conditions than
# production is not verification; the uid is part of the contract.
USER_ARG=(--user "$(id -u):$(id -g)")

probe() { # probe <name> <command…>; echoes "name<TAB>status<TAB>version"
  local name="$1"; shift
  local out rc
  out="$("$DOCKER" run --rm "${USER_ARG[@]}" --entrypoint sh "$TAG" -c "$* 2>&1 | head -1" 2>&1)" && rc=0 || rc=$?
  if [ "${rc:-0}" -ne 0 ] || [ -z "$out" ]; then
    printf '%s\tMISSING\t%s\n' "$name" "${out:-no output}"
  else
    printf '%s\tOK\t%s\n' "$name" "$out"
  fi
}

log "verifying engines inside $TAG"
RESULTS="$(
  probe opengrep      'opengrep --version'
  probe ast-grep      'ast-grep --version'
  probe clippy        'cargo clippy --version'
  probe clippy-sarif  'clippy-sarif --version'
  probe cargo-audit   'cargo audit --version'
  probe cargo-geiger  'cargo geiger --version'
  probe cargo-dylint  'cargo dylint --version'
)"
printf '%s\n' "$RESULTS" | awk -F'\t' '{printf "    %-14s %-8s %s\n", $1, $2, $3}'

# Rule packs and prebuilt lint libs are data, not binaries — verify them separately or a run scans
# with an engine present and its rules absent, which is the worst of both worlds.
# A `--version` call can succeed on an engine that dies the moment it needs its cache: OpenGrep only
# unpacks `$HOME/.cache/opengrep/<ver>/opengrep.bin` on FIRST REAL USE. So probe the precondition
# directly, and then actually scan something.
log "verifying runtime preconditions under the production uid ($(id -u):$(id -g))"
PRECOND="$("$DOCKER" run --rm "${USER_ARG[@]}" --entrypoint sh "$TAG" -c '
  printf "HOME=%s\n" "${HOME:-unset}"
  if touch "$HOME/.probe" 2>/dev/null; then echo "home_writable YES"; rm -f "$HOME/.probe";
  else echo "home_writable NO"; fi
  if mkdir -p "${XDG_CACHE_HOME:-$HOME/.cache}/probe" 2>/dev/null; then echo "cache_writable YES";
  else echo "cache_writable NO"; fi
  # run-all.sh copies the read-only /src mount into a writable /work before any engine compiles.
  if mkdir -p /work/probe 2>/dev/null; then echo "work_writable YES"; rmdir /work/probe;
  else echo "work_writable NO"; fi' 2>&1)"
printf '%s\n' "$PRECOND" | sed 's/^/    /'

SMOKE_DIR="$(mktemp -d)"; printf 'fn main() { let _v = vec![0u8; 8]; }\n' > "$SMOKE_DIR/smoke.rs"
# `|| true` is load-bearing: under `set -e` a failing command substitution aborts the script, so the
# first version of this probe killed the run silently at exactly the moment it found a real defect.
# Same env as run-all.sh: OpenGrep bundles a Python that falls back to the ASCII codec and dies on any
# non-ASCII rule file, so production exports a UTF-8 locale. A probe without it is a different test.
SMOKE="$("$DOCKER" run --rm "${USER_ARG[@]}" --network none \
          -e LC_ALL=C.UTF-8 -e LANG=C.UTF-8 -v "$SMOKE_DIR:/smoke:ro" \
          --entrypoint sh "$TAG" -c 'opengrep scan --quiet --config /opt/rulepacks/trailofbits-semgrep/rs \
               --json /smoke >/dev/null 2>/tmp/e && echo "opengrep_scan OK" \
             || { echo "opengrep_scan FAILED rc=$?"; head -3 /tmp/e; }' 2>&1 || true)"
# The config is the exact path run-all.sh scans (`…/trailofbits-semgrep/rs`), not the pack root: on
# the root, opengrep exits 7 = MISSING_CONFIG because no rule file applies there, and run-all.sh maps
# any non-zero rc to status=error. Probing a path production never uses re-invents the failure.
rm -rf "$SMOKE_DIR"
printf '%s\n' "$SMOKE" | sed 's/^/    /'

log "verifying rule packs / prebuilt artefacts"
# Paths must match the Dockerfile EXACTLY. The first draft of this probe looked for
# `/opt/rulepacks/trailofbits` while the Dockerfile clones `/opt/rulepacks/trailofbits-semgrep`, and
# duly reported a present pack as ABSENT — a verifier that is wrong in the alarming direction still
# costs a debugging session, so these are asserted against the Dockerfile, not from memory.
ASSETS="$("$DOCKER" run --rm --entrypoint sh "$TAG" -c '
  for p in /opt/rulepacks/trailofbits-semgrep /opt/rulepacks/dylint \
           /opt/sast/dylint-libs /opt/sast/advisory-db /opt/sast/clippy-lints.json \
           /opt/rulepacks/semgrep-rules; do
    if [ -e "$p" ]; then
      n=$(find "$p" -type f 2>/dev/null | wc -l)
      echo "$p PRESENT ${n}files"
    else
      echo "$p ABSENT -"
    fi
  done')"
printf '%s\n' "$ASSETS" | awk '{printf "    %-40s %-8s %s\n", $1, $2, $3}'

# ── manifest: pin what a later run is allowed to claim ───────────────────────────────────────────
DIGEST="$("$DOCKER" image inspect --format '{{index .Id}}' "$TAG")"
MANIFEST="$HERE/engine-manifest.json"
ENGINES_TSV="$RESULTS" ASSETS_TSV="$ASSETS" IMAGE="$TAG" IMAGE_ID="$DIGEST" \
python3 - "$MANIFEST" <<'PY'
import json, os, sys
def rows(env, keys, sep=None):
    out = []
    for line in os.environ.get(env, "").splitlines():
        if not line.strip():
            continue
        parts = line.split(sep) if sep else line.split(None, 2)
        parts += [""] * (len(keys) - len(parts))
        out.append(dict(zip(keys, (p.strip() for p in parts))))
    return out
json.dump({
    "image": os.environ["IMAGE"],
    "image_id": os.environ["IMAGE_ID"],
    "built_by": "docker/sast/build.sh",
    "engines": rows("ENGINES_TSV", ("name", "status", "version"), "\t"),
    "assets":  rows("ASSETS_TSV",  ("path", "status", "files")),
}, open(sys.argv[1], "w"), indent=2)
PY
log "wrote $MANIFEST"

# ── gate ─────────────────────────────────────────────────────────────────────────────────────────
FAILED=0
for e in "${CORE_ENGINES[@]}"; do
  printf '%s\n' "$RESULTS" | grep -qP "^\Q$e\E\tOK\t" || { echo "CORE engine missing: $e" >&2; FAILED=1; }
done
if [ "$STRICT" -eq 1 ]; then
  for e in "${MEASUREMENT_ENGINES[@]}"; do
    printf '%s\n' "$RESULTS" | grep -qP "^\Q$e\E\tOK\t" \
      || { echo "MEASUREMENT engine missing under --strict: $e" >&2; FAILED=1; }
  done
fi

# Assets are gated, not merely printed. The first version of this script listed them and exited 0 —
# and passed a build whose `dylint-libs` held ZERO files, i.e. cargo-dylint installed, verified, and
# structurally unable to report anything. An engine without its rules is the failure this whole layer
# is meant to make impossible, so it has to fail the gate, not appear in a table someone may read.
# A directory that exists but is empty counts as missing; "PRESENT 0files" is the exact shape of the
# defect.
asset_ok() { # asset_ok <path>  → present AND non-empty
  printf '%s\n' "$ASSETS" | awk -v p="$1" '$1==p && $2=="PRESENT" && $3!="0files" {found=1} END{exit !found}'
}
for a in /opt/rulepacks/trailofbits-semgrep /opt/sast/clippy-lints.json /opt/sast/advisory-db; do
  asset_ok "$a" || { echo "REQUIRED asset missing or empty: $a" >&2; FAILED=1; }
done

# Runtime preconditions are gated too — an unwritable cache is a silent 0-hit corpus run.
printf '%s\n' "$PRECOND" | grep -q '^home_writable YES'  || { echo "HOME not writable under the production uid" >&2; FAILED=1; }
printf '%s\n' "$PRECOND" | grep -q '^cache_writable YES' || { echo "cache dir not writable under the production uid" >&2; FAILED=1; }
printf '%s\n' "$PRECOND" | grep -q '^work_writable YES'  || { echo "/work not writable under the production uid (run-all.sh cannot stage the crate)" >&2; FAILED=1; }
printf '%s\n' "$SMOKE"   | grep -q '^opengrep_scan OK'   || { echo "opengrep cannot actually scan (see smoke output above)" >&2; FAILED=1; }
if [ "$STRICT" -eq 1 ]; then
  # dylint without its prebuilt libraries is the empty-engine case above.
  asset_ok /opt/sast/dylint-libs \
    || { echo "MEASUREMENT asset missing or empty under --strict: /opt/sast/dylint-libs" >&2; FAILED=1; }
fi
[ "$FAILED" -eq 0 ] || die "engine verification failed — do NOT compare a run from this image to an older one"

log "OK — $TAG verified"
