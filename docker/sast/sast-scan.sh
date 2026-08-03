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
# userns-remap defence (L59, and the exact wall preflight-deploy.sh's writeback canary flags).
# Under a daemon with `userns-remap`, a container started with `--user $(id -u)` does NOT run as this
# user — its uid is shifted into the SUBORDINATE range (e.g. host 300000+uid), so it cannot write into
# these host-user-owned bind mounts. Every engine then fails "/out/...: Permission denied", cargo fetch
# silently caches nothing, and normalize aborts — an hour of scan producing zero artifacts. 0777
# (no sticky bit) lets whichever uid the container maps to write, and still lets THIS user delete the
# tree afterwards. On a normal daemon `--user` already IS this user, so the mode change is inert.
# (Nested cargo-cache subdirs the container creates may still be remap-owned; on a userns box their
# cleanup can need the operator's sudo — a known userns tradeoff, not a scan-blocking failure.)
chmod 0777 "$OUT" "$OUT/raw" "$CARGO_RO" 2>/dev/null || true

echo "=== sast-driven: $NAME @ ${COMMIT:0:12} ==="
echo "    src=$SRC_DIR"
echo "    out=$OUT"

# ── deploy-layer preflight (L59): settle the daemon's traps in seconds, not an hour into the build.
# image-present / export-canary / egress-canary / result-writeback — each with a named remediation.
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
"$SCRIPT_DIR/../../scripts/preflight-deploy.sh" "$IMAGE" "$OUT/raw" || {
  echo "deploy-preflight failed — aborting before the expensive scan (remediation printed above)"; exit 3; }

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
    # NOT an `&&` chain, and NOT `cp -a`. `/w` is pre-created in the image (an arbitrary uid cannot
    # mkdir at `/`), so `cp -a` tries to preserve timestamps on a directory it does not own and exits
    # non-zero — which silently skipped `cargo fetch` while the copy itself had actually succeeded.
    # `cp -R` copies the contents and makes no claim on the attributes of the destination itself.
    mkdir -p /w; cp -R /src/. /w/ 2>/dev/null || true
    cd /w
    # Warm the graph the ANALYZE phase will have to resolve OFFLINE, with the same feature set it
    # will use. Measured on actix-web: clippy runs `--all-features`, the committed Cargo.lock lags
    # its Cargo.toml, and `cargo fetch` alone resolves only the default features — so offline clippy
    # re-resolved, could not find `actix-service` in the seeded index, wrote an empty SARIF and
    # (pipe exit code) reported success. clippy is 84 % of the archived hit volume, so this silently
    # emptied the dominant engine on every workspace crate.
    #   * `generate-lockfile` refreshes the lock while the network is up. It may move dep versions
    #     off what the crate committed; that is acceptable here — the engines lint the source of the
    #     crate itself, and an unresolvable graph costs the whole engine.
    #   * `metadata --all-features` forces the index cache to cover optional/feature-gated packages.
    cargo generate-lockfile 2>&1 | tail -2
    (cargo fetch --locked || cargo fetch) 2>&1 | tail -5
    cargo metadata --all-features --format-version 1 >/dev/null 2>&1 \
      || echo "metadata --all-features failed (offline clippy may re-resolve)"
    # `cargo fetch` RESOLVES the graph and writes Cargo.lock — but into this throwaway copy, which
    # dies with the container. Library crates mostly do not commit a lock, so the analyze phase then
    # had none, and two engines lost on it: cargo-audit reads the lock directly (recorded "absent"),
    # and cargo-geiger resolves the graph itself, so it reached for the registry index and died
    # against `--network none` (rc=101, "Could not resolve host: index.crates.io"). Regenerating it
    # offline later does not work — the seeded registry is a download cache, not a usable index.
    # So keep the lock produced HERE, where the network exists, in the volume that survives.
    [ -f /w/Cargo.lock ] && cp -f /w/Cargo.lock /cargo/Cargo.lock.generated 2>/dev/null || true
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

# ── CodeQL (BYOL): mount a host CodeQL CLI distribution if the operator provides one ──────────────
# CodeQL's CLI is proprietary and unredistributable, so it is NEVER in the image. Point
# SAST_CODEQL_CLI at a host CodeQL distribution (the dir holding the `codeql` binary, or the binary
# itself) — the `sast-driven` skill's `--byol codeql` flag sets this — and it is mounted read-only at
# /opt/codeql for the analyze phase, with the engine auto-selected. Our Rust queries ship in the
# already-mounted /rules/codeql/rust; no extra mount is needed for them. Absent by default.
ENGINES_SEL="${SAST_ENGINES:-opengrep,astgrep,clippy,audit,dylint,geiger}"
CODEQL_ARGS=""
if [ -n "${SAST_CODEQL_CLI:-}" ]; then
  if [ -d "$SAST_CODEQL_CLI" ]; then CLI_DIR="$SAST_CODEQL_CLI"; else CLI_DIR="$(dirname "$SAST_CODEQL_CLI")"; fi
  if [ -x "$CLI_DIR/codeql" ]; then
    CODEQL_ARGS="-v $CLI_DIR:/opt/codeql:ro -e CODEQL_CLI=/opt/codeql/codeql"
    [ -n "${CODEQL_CREATE_FLAGS:-}" ] && CODEQL_ARGS="$CODEQL_ARGS -e CODEQL_CREATE_FLAGS=${CODEQL_CREATE_FLAGS}"
    case ",$ENGINES_SEL," in *,codeql,*) : ;; *) ENGINES_SEL="$ENGINES_SEL,codeql" ;; esac
    echo "      CodeQL BYOL: $CLI_DIR → /opt/codeql (engine enabled; engines=$ENGINES_SEL)"
  else
    echo "      ⚠ SAST_CODEQL_CLI set but no executable 'codeql' at $CLI_DIR — CodeQL skipped"
  fi
fi

# ── phase 2: analyze (network OFF — this is where target code executes) ──────
echo "[2/2] analyze (network none, sandbox=$SANDBOX)"
docker run --rm $RUNTIME_ARGS $CODEQL_ARGS \
  --user "$(id -u):$(id -g)" \
  --network none \
  --memory "${SAST_MEMORY:-8g}" \
  --cpus "${SAST_CPUS:-6}" \
  -v "$SRC_DIR:/src:ro" \
  -v "$CARGO_RO:/cargo" \
  -v "$OUT:/out" \
  -v "${SAST_RULES:-$HOME/rip-sast/rules}:/rules:ro" \
  -e CARGO_HOME=/cargo \
  -e SAST_CRATE="$NAME" -e SAST_COMMIT="$COMMIT" \
  -e SAST_ENGINES="$ENGINES_SEL" \
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
