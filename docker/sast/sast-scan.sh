#!/usr/bin/env bash
# sast-scan.sh — host-side driver for the `sast-driven` mode.
#
#   ./sast-scan.sh <name> <git-url> <commit> [out-root]
#   ./sast-scan.sh <name> --local <path>    [out-root]
#
# Two phases, and the split is the security contract (docs/sast-layer.md §8.3):
#
#   1. FETCH   — network ON, `cargo fetch --locked` only. Cargo RESOLVES and DOWNLOADS; it does not
#                build, so no `build.rs` and no proc-macro of the target executes here.
#   2. ANALYZE — network OFF (`--network none`). This is where clippy/dylint compile the crate and
#                therefore DO execute its build scripts — with no network, under gVisor when the
#                host provides it.
#
# Never inverted: nothing that executes target code ever gets network.
set -u -o pipefail

IMAGE=${SAST_IMAGE:-vuln-pipeline-sast:v1}
NAME=${1:?usage: sast-scan.sh <name> <git-url> <commit> [out-root]}
OUT_ROOT=${4:-$HOME/rip-sast/results}
WORK=${SAST_WORK:-$HOME/rip-sast/work}

if [ "${2:-}" = "--local" ]; then
  SRC_DIR=$(cd "${3:?path required}" && pwd); COMMIT=$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo local)
  OUT_ROOT=${4:-$HOME/rip-sast/results}
else
  URL=${2:?git url required}; COMMIT=${3:?commit required}
  SRC_DIR="$WORK/src/$NAME"
  if [ ! -d "$SRC_DIR/.git" ]; then
    mkdir -p "$(dirname "$SRC_DIR")"
    echo "[clone] $URL → $SRC_DIR"
    git clone --quiet "$URL" "$SRC_DIR" || { echo "clone FAILED"; exit 1; }
  fi
  git -C "$SRC_DIR" fetch --quiet --all --tags 2>/dev/null
  if [ "$COMMIT" = "HEAD" ]; then
    git -C "$SRC_DIR" checkout --quiet "$(git -C "$SRC_DIR" symbolic-ref --short refs/remotes/origin/HEAD 2>/dev/null | sed 's|origin/||' || echo main)" 2>/dev/null \
      || git -C "$SRC_DIR" checkout --quiet master 2>/dev/null
    git -C "$SRC_DIR" pull --quiet --ff-only 2>/dev/null
  else
    git -C "$SRC_DIR" checkout --quiet --detach "$COMMIT" || { echo "checkout $COMMIT FAILED"; exit 1; }
  fi
  # Always record the RESOLVED sha — a `HEAD` ref must not stay "HEAD" in the manifest, or two runs
  # a week apart look identical while scoring different trees.
  COMMIT=$(git -C "$SRC_DIR" rev-parse HEAD)
fi

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$OUT_ROOT/$NAME/$STAMP"
CARGO_RO="$WORK/cargo/$NAME"
mkdir -p "$OUT/raw" "$CARGO_RO"

echo "=== sast-driven: $NAME @ ${COMMIT:0:12} ==="
echo "    src=$SRC_DIR"
echo "    out=$OUT"

# ── phase 1: fetch (network ON, nothing executes) ────────────────────────────
echo "[1/2] cargo fetch (network on, no build)"
# Work on a COPY: crates that don't commit a Cargo.lock make cargo want to write one, and the clone
# is mounted read-only by design. Only the populated registry in /cargo needs to survive.
# `--user` matters more than it looks. Without it the container runs as ROOT and everything it writes
# into the bind-mounted cargo home is root-owned — so the box's own operator cannot delete their own
# scratch directory. Measured the hard way: 2.9 GB of prefetch cache became undeletable by its owner,
# and clearing it required borrowing an unrelated container image. A tool that leaves litter its user
# cannot remove eventually fills the disk, and this one is at 91 % on a box shared with other
# people's long-running containers.
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$SRC_DIR:/src:ro" -v "$CARGO_RO:/cargo" \
  -e CARGO_HOME=/cargo \
  "$IMAGE" \
  sh -c '
    cp -a /src /w && cd /w && (cargo fetch --locked || cargo fetch) 2>&1 | tail -5
    # Warm the Dylint DRIVER here too. Dylint compiles a driver per toolchain on first use, which
    # needs network — and the analyze phase has none. Park it in the mounted cargo volume via
    # DYLINT_DRIVER_PATH so it survives into the offline phase. Still no target build script runs:
    # the driver is dylint own code, compiled against the pinned nightly.
    L=$(find /opt/rulepacks/dylint /opt/sast -name "lib*@*.so" 2>/dev/null | head -1)
    if [ -n "$L" ]; then
      mkdir -p /cargo/dylint-drivers
      DYLINT_DRIVER_PATH=/cargo/dylint-drivers DYLINT_LIBRARY_PATH=$(dirname "$L") \
        cargo dylint --lib-path "$L" 2>&1 | tail -3
      echo "dylint drivers: $(find /cargo/dylint-drivers -type f | wc -l) file(s)"
    fi
  ' > "$OUT/raw/fetch.log" 2>&1
FETCH_RC=$?
echo "      rc=$FETCH_RC ($(du -sh "$CARGO_RO" 2>/dev/null | cut -f1) cached)"

# ── sandbox selection: gVisor if the host has it, otherwise say so out loud ──
RUNTIME_ARGS=""; SANDBOX="docker-default"
if docker info --format '{{json .Runtimes}}' 2>/dev/null | grep -q runsc; then
  RUNTIME_ARGS="--runtime=runsc"; SANDBOX="gvisor"
else
  echo "      ⚠ gVisor (runsc) not registered on this host — analyze phase compiles the target's"
  echo "        build scripts under the default runtime. Recorded as sandbox=docker-default."
fi

# ── phase 2: analyze (network OFF — this is where target code executes) ──────
echo "[2/2] analyze (network none, sandbox=$SANDBOX)"
docker run --rm $RUNTIME_ARGS \
  --user "$(id -u):$(id -g)" \
  --network none \
  --memory "${SAST_MEMORY:-8g}" \
  --cpus "${SAST_CPUS:-6}" \
  -v "$SRC_DIR:/src:ro" \
  -v "$CARGO_RO:/cargo-ro:ro" \
  -v "$OUT:/out" \
  -v "${SAST_RULES:-$HOME/rip-sast/rules}:/rules:ro" \
  -e SAST_CRATE="$NAME" -e SAST_COMMIT="$COMMIT" \
  -e SAST_ENGINES="${SAST_ENGINES:-opengrep,astgrep,clippy,audit,dylint,geiger}" \
  -e SAST_TIMEOUT="${SAST_TIMEOUT:-1800}" \
  -e SAST_JOBS="${SAST_JOBS:-6}" \
  "$IMAGE" 2>&1 | tee "$OUT/run.log"

# ── run manifest: the score key (corpus_rev, image_digest, rule_pack_rev) ────
python3 - "$OUT" "$IMAGE" "$NAME" "$COMMIT" "$SANDBOX" "$FETCH_RC" <<'PY'
import json, subprocess, sys, pathlib
out, image, name, commit, sandbox, fetch_rc = sys.argv[1:7]
def sh(*c):
    try: return subprocess.run(c, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception: return ""
digest = sh("docker", "image", "inspect", image, "--format", "{{.Id}}")
engines = []
p = pathlib.Path(out) / "engines.jsonl"
if p.exists():
    engines = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
json.dump({
    "crate": name, "commit": commit, "image": image, "image_digest": digest,
    "sandbox": sandbox, "fetch_rc": int(fetch_rc), "engines": engines,
    "engines_ok": [e["engine"] for e in engines if e.get("status") == "ok"],
    "engines_absent": [e["engine"] for e in engines if e.get("status") == "absent"],
    "engines_failed": [e["engine"] for e in engines if e.get("status") in ("error", "timeout")],
    # A partial engine produced a well-formed artifact from a TRUNCATED scan. Its counts are not
    # comparable across crates and must not enter a yield ledger — surfaced separately so the number
    # is never quoted as a complete one.
    "engines_partial": [e["engine"] for e in engines if e.get("status") == "partial"],
}, open(f"{out}/manifest.json", "w"), indent=2)
print("\n=== manifest ===")
print(json.dumps({k: v for k, v in json.load(open(f"{out}/manifest.json")).items()
                  if k != "engines"}, indent=2))
PY

echo "=== results: $OUT ==="
