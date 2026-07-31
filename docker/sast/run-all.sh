#!/usr/bin/env bash
# run-all.sh — the `sast-driven` mode's in-image entrypoint.
#
# Runs EVERY available engine with its DEFAULT rules over /src (read-only), writes raw per-engine
# output to /out/raw/, and records exactly what ran in /out/engines.jsonl.
#
# Two disciplines, both load-bearing:
#   * NO SILENT SKIP — an engine that is absent, times out, or exits non-zero is RECORDED with its
#     rc and stderr tail. A missing engine must never look like "clean".
#   * NO EARLY EXIT — one engine failing must not cost the other five. Hence `set -u` without `-e`.
#
# Knobs (env):
#   SAST_ENGINES=opengrep,astgrep,clippy,audit,dylint,geiger   (default: all present)
#   SAST_TIMEOUT=1800     per-engine wall-clock seconds
#   SAST_JOBS=4           parallelism where the tool supports it
#   SAST_CLIPPY_GROUPS="all pedantic nursery cargo"            v1 = everything; prune later
set -u -o pipefail

SRC_RO=${SRC_RO:-/src}
SRC=${SRC:-/work}          # writable copy — see below
OUT=${OUT:-/out}
RULES=${RULES:-/rules}
TIMEOUT=${SAST_TIMEOUT:-1800}
JOBS=${SAST_JOBS:-4}
ENGINES=${SAST_ENGINES:-opengrep,astgrep,clippy,audit,dylint,geiger}
CLIPPY_GROUPS=${SAST_CLIPPY_GROUPS:-"all pedantic nursery cargo"}

mkdir -p "$OUT/raw"
: > "$OUT/engines.jsonl"

# OpenGrep bundles its own Python runtime, which falls back to the ASCII codec when the container has
# no UTF-8 locale — it then dies with UnicodeDecodeError on any rule file containing a non-ASCII
# character (an em-dash in a rule's `message:` is enough). Measured on the first real run.
export LANG=${LANG:-C.UTF-8} LC_ALL=${LC_ALL:-C.UTF-8} PYTHONUTF8=1 PYTHONIOENCODING=utf-8

want() { case ",$ENGINES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

# record <engine> <status> <rc> <seconds> <artifact> <note>
record() {
  python3 - "$@" <<'PY' >> "$OUT/engines.jsonl"
import json, sys
engine, status, rc, secs, artifact, note = sys.argv[1:7]
print(json.dumps({"engine": engine, "status": status, "rc": int(rc),
                  "seconds": float(secs), "artifact": artifact, "note": note[:800]}))
PY
}

# run_fb <engine> <artifact> <primary-sh> <fallback-sh>
# Several of these tools moved their flags between versions (opengrep forked semgrep and dropped
# telemetry flags; cargo-audit's JSON switch changed spelling). Rather than pin a guess, try the rich
# invocation and fall back to the minimal one — and RECORD which variant worked, so the manifest says
# what actually ran instead of implying the primary did.
run_fb() {
  local engine=$1 artifact=$2 primary=$3 fallback=$4
  run "$engine" "$artifact" -- sh -c "$primary"
  local st
  st=$(tail -1 "$OUT/engines.jsonl" | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' 2>/dev/null || echo error)
  if [ "$st" != "ok" ] && [ -n "$fallback" ]; then
    echo "   ↻ $engine: primary invocation failed ($st) — retrying with minimal flags"
    run "$engine-fb" "$artifact" -- sh -c "$fallback"
  fi
}

# run <engine> <artifact> -- <cmd...>
run() {
  local engine=$1 artifact=$2; shift 3
  local t0 rc note
  echo "── $engine ─────────────────────────────────────────────────────────────"
  t0=$(date +%s)
  timeout "$TIMEOUT" "$@" > "$OUT/raw/$engine.stdout" 2> "$OUT/raw/$engine.stderr"
  rc=$?
  local secs=$(( $(date +%s) - t0 ))
  note=$(tail -c 700 "$OUT/raw/$engine.stderr" 2>/dev/null | tr '\n' ' ')
  local status="ok"
  [ "$rc" -eq 124 ] && status="timeout"
  [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ] && status="error"
  [ -s "$OUT/raw/$artifact" ] || { [ "$status" = "ok" ] && status="empty"; }
  # TRUNCATION DETECTION. A cargo-based engine that aborts mid-scan still writes a well-formed
  # artifact, and when it runs in a pipe (`cargo clippy | clippy-sarif`) the pipeline's exit code is
  # the *last* command's — so a truncated scan reports rc=0 and looks complete. Measured: clippy
  # aborted on hyper at an example target and on h2 at `deny(warnings)` under cfg(test), yielding
  # 82 vs 1593 hits that reflected WHEN each abort happened, not the code. A partial scan must never
  # be presented as a clean one.
  if [ "$status" = "ok" ] && grep -qE "could not compile|build failed|error: aborting" \
       "$OUT/raw/$engine.stderr" 2>/dev/null; then
    status="partial"
  fi
  record "$engine" "$status" "$rc" "$secs" "$artifact" "$note"
  echo "   → $status (rc=$rc, ${secs}s) $artifact"
}

echo "=== sast-driven run: $(date -u +%FT%TZ) ==="
cat /opt/sast/VERSIONS.txt 2>/dev/null | sed 's/^/    /'

# The clippy lint catalogue is the attribution key for pruning. Generate it here rather than at image
# build time: it costs ~2s, and regenerating it does not require rebuilding 4.5 GB of tool layers
# when the parser is fixed.
# Regenerate on a PLAUSIBILITY floor, not on "is it empty": the v1 image shipped a catalogue with 4
# lints (a broken regex matched a couple of stray lines), which an emptiness check happily accepted
# and every hit came out `unattributed`. clippy has ~800 lints; anything under 100 is a parse failure.
CAT_N=$(python3 -c 'import json;print(len(json.load(open("/opt/sast/clippy-lints.json"))))' 2>/dev/null || echo 0)
if [ "${CAT_N:-0}" -lt 100 ]; then
  python3 /opt/sast/lint_catalog.py /tmp/clippy-lints.json 2>&1 | sed 's/^/    /'
  cp /tmp/clippy-lints.json /opt/sast/clippy-lints.json 2>/dev/null || true
fi

# ── writable working copy ─────────────────────────────────────────────────────────────────────────
# The target is mounted READ-ONLY on purpose (we must never write into the operator's clone), but
# cargo insists on writing: Cargo.lock for crates that don't commit one, and `target/`. So analyse a
# copy. The mount stays pristine; `--src /work` tells the normalizer to strip that prefix, so emitted
# paths remain repo-relative and comparable across runs.
if [ -d "$SRC_RO" ] && [ ! -d "$SRC" ]; then
  cp -a "$SRC_RO" "$SRC" 2>/dev/null || { mkdir -p "$SRC"; cp -a "$SRC_RO"/. "$SRC"/; }
  echo "    working copy: $SRC_RO → $SRC ($(du -sh "$SRC" 2>/dev/null | cut -f1))"
fi

# ── writable cargo home: the prefetched registry arrives read-only, cargo needs to write locks ────
export CARGO_HOME=${CARGO_HOME:-/tmp/cargo}
export CARGO_TARGET_DIR=/tmp/target
mkdir -p "$CARGO_HOME" "$CARGO_TARGET_DIR"
if [ -d /cargo-ro ]; then
  cp -a /cargo-ro/. "$CARGO_HOME"/ 2>/dev/null || true
  echo "    cargo home seeded from /cargo-ro ($(du -sh "$CARGO_HOME" 2>/dev/null | cut -f1))"
fi
# The advisory DB was baked into the image at /root/.cargo/advisory-db.
[ -d /root/.cargo/advisory-db ] && cp -a /root/.cargo/advisory-db "$CARGO_HOME"/ 2>/dev/null || true

# ── 1. OpenGrep — upstream default rule packs, out of the box ─────────────────────────────────────
if want opengrep && command -v opengrep >/dev/null; then
  for pack in \
      "semgrep-rust:/opt/rulepacks/semgrep-rules/rust" \
      "semgrep-generic:/opt/rulepacks/semgrep-rules/generic" \
      "tob-rs:/opt/rulepacks/trailofbits-semgrep/rs" \
      "own:$RULES/opengrep" ; do
    name=${pack%%:*}; path=${pack#*:}
    [ -d "$path" ] || { record "opengrep-$name" "absent" 0 0 "" "no rule pack at $path"; continue; }
    out="$OUT/raw/opengrep-$name.sarif"
    # `--metrics` does NOT exist in OpenGrep — the fork stripped semgrep's telemetry entirely
    # (measured: `unknown option '--metrics'`). Nothing to opt out of.
    run_fb "opengrep-$name" "opengrep-$name.sarif" \
      "opengrep scan --config '$path' --sarif --output '$out' --jobs $JOBS --timeout 300 '$SRC'" \
      "opengrep scan --config '$path' --sarif --output '$out' '$SRC'"
  done
else
  record "opengrep" "absent" 0 0 "" "binary not present or engine deselected"
fi

# ── 2. ast-grep — our enumerator rules (upstream ships no default pack) ───────────────────────────
if want astgrep && command -v ast-grep >/dev/null; then
  if [ -f "$RULES/astgrep/sgconfig.yml" ]; then
    # Redirect INSIDE the command: run() evaluates the artifact's emptiness immediately, so a
    # post-hoc `cp` from stdout would always be judged "empty".
    run_fb "astgrep" "astgrep.json" \
      "cd '$RULES/astgrep' && ast-grep scan --json=stream '$SRC' > '$OUT/raw/astgrep.json'" \
      "ast-grep scan -c '$RULES/astgrep/sgconfig.yml' --json=stream '$SRC' > '$OUT/raw/astgrep.json'"
  else
    record "astgrep" "absent" 0 0 "" "no $RULES/astgrep/sgconfig.yml mounted"
  fi
else
  record "astgrep" "absent" 0 0 "" "binary not present or engine deselected"
fi

# ── 3. clippy — EVERY group (v1 premise: all defaults, prune from measured yield) ─────────────────
if want clippy && cargo clippy --version >/dev/null 2>&1; then
  CLIPPY_FLAGS=""
  for g in $CLIPPY_GROUPS; do CLIPPY_FLAGS="$CLIPPY_FLAGS -W clippy::$g"; done
  # The security-relevant slice of `restriction` (never the whole group — upstream warns it is
  # deliberately excessive and self-contradictory).
  for l in unwrap_used expect_used panic indexing_slicing arithmetic_side_effects \
           as_conversions undocumented_unsafe_blocks missing_safety_doc \
           mem_forget exit unwrap_in_result; do
    CLIPPY_FLAGS="$CLIPPY_FLAGS -W clippy::$l"
  done
  # Two deliberate choices, both learned from a truncated first batch:
  #   --cap-lints=warn : crates that carry `#![cfg_attr(test, deny(warnings))]` (h2 does) turn every
  #                      lint we add with -W into a hard ERROR, and the compile aborts partway —
  #                      silently truncating the scan. Capping keeps them warnings.
  #   no --all-targets : examples and tests are dropped by the structural filter downstream anyway,
  #                      so scanning them buys nothing and risks aborting the whole run on an
  #                      unrelated example that does not compile (hyper's `hello-http2` did exactly
  #                      that, cutting the scan to 82 hits).
  run_fb "clippy" "clippy.sarif" \
    "cd '$SRC' && cargo clippy --offline --all-features --message-format=json -- --cap-lints=warn $CLIPPY_FLAGS | clippy-sarif > '$OUT/raw/clippy.sarif'" \
    "cd '$SRC' && cargo clippy --offline --message-format=json -- --cap-lints=warn $CLIPPY_FLAGS | clippy-sarif > '$OUT/raw/clippy.sarif'"
else
  record "clippy" "absent" 0 0 "" "clippy not present or engine deselected"
fi

# ── 4. cargo-audit — RustSec advisories against the pinned lockfile, offline ──────────────────────
if want audit && command -v cargo-audit >/dev/null; then
  if [ -f "$SRC/Cargo.lock" ]; then
    run_fb "audit" "audit.json" \
      "cargo audit --no-fetch --json --file '$SRC/Cargo.lock' > '$OUT/raw/audit.json'" \
      "cd '$SRC' && cargo audit -n -f json > '$OUT/raw/audit.json'"
  else
    record "audit" "absent" 0 0 "" "no Cargo.lock at $SRC (library crate — run after cargo fetch)"
  fi
else
  record "audit" "absent" 0 0 "" "cargo-audit not present or engine deselected"
fi

# ── 5. Dylint — type-aware lints (trailofbits `general` library, pre-built into the image) ────────
if want dylint && command -v cargo-dylint >/dev/null; then
  # Dylint builds its libraries into a WORKSPACE-level target dir, not the member's — locate them by
  # their `lib<name>@<toolchain>.so` naming rather than assuming a path (the v1 image's prebuild
  # "failed" for exactly this reason: the build succeeded, the copy globbed the wrong directory).
  # Only libraries that EXPORT `dylint_version` are loadable. A workspace like trailofbits' `general`
  # builds one umbrella lib plus a `.so` per member, and the members do NOT export that symbol —
  # handing dylint the whole directory makes it abort with "could not find dylint_version" for every
  # member and lose the umbrella too. Filter by the symbol rather than by naming convention.
  mkdir -p /tmp/dylint-libs
  for so in $(find /opt/rulepacks/dylint /opt/sast -name 'lib*@*.so' 2>/dev/null); do
    if nm -D --defined-only "$so" 2>/dev/null | grep -q dylint_version; then
      ln -sf "$so" /tmp/dylint-libs/ 2>/dev/null || true
    fi
  done
  DL=/tmp/dylint-libs
  LIBS=$(find "$DL" -maxdepth 1 -name 'lib*@*.so' 2>/dev/null | wc -l)
  # The per-toolchain driver was pre-built during the networked fetch phase into the cargo volume;
  # without it, dylint tries to compile one here and dies against `--network none`.
  export DYLINT_DRIVER_PATH="$CARGO_HOME/dylint-drivers"
  DRIVERS=$(find "$DYLINT_DRIVER_PATH" -type f 2>/dev/null | wc -l)
  if [ "${LIBS:-0}" -gt 0 ]; then
    echo "    dylint: $LIBS lint libs in $DL, ${DRIVERS:-0} prebuilt driver file(s)"
    [ "${DRIVERS:-0}" -eq 0 ] && echo "    ⚠ no prebuilt driver — dylint will likely fail offline"
    run_fb "dylint" "dylint.json" \
      "cd '$SRC' && DYLINT_LIBRARY_PATH='$DL' cargo dylint --all -- --message-format=json > '$OUT/raw/dylint.json'" \
      "cd '$SRC' && for l in '$DL'/lib*@*.so; do DYLINT_LIBRARY_PATH='$DL' cargo dylint --lib-path \"\$l\" -- --message-format=json; done > '$OUT/raw/dylint.json'"
  else
    record "dylint" "absent" 0 0 "" "no prebuilt lint libs in the image (see BUILD-FAILURES.txt)"
  fi
else
  record "dylint" "absent" 0 0 "" "cargo-dylint not present or engine deselected"
fi

# ── 6. cargo-geiger — unsafe-surface inventory (U1 material). Slow: opt-in. ───────────────────────
if want geiger && command -v cargo-geiger >/dev/null; then
  run_fb "geiger" "geiger.json" \
    "cd '$SRC' && cargo geiger --offline --output-format Json > '$OUT/raw/geiger.json'" \
    "cd '$SRC' && cargo geiger --output-format Json --offline --all-features > '$OUT/raw/geiger.json'"
else
  record "geiger" "absent" 0 0 "" "cargo-geiger not present or engine deselected"
fi

# ── normalize: raw → hits.jsonl → cells.jsonl → summary.json ──────────────────────────────────────
echo "── normalize ───────────────────────────────────────────────────────────"
python3 /opt/sast/normalize.py --out "$OUT" --src "$SRC" \
  --crate "${SAST_CRATE:-unknown}" --commit "${SAST_COMMIT:-unknown}" \
  || echo "normalize FAILED — raw artifacts are still in $OUT/raw"

echo "=== done: $(date -u +%FT%TZ) ==="
[ -f "$OUT/summary.json" ] && cat "$OUT/summary.json"
exit 0
