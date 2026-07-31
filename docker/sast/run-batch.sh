#!/usr/bin/env bash
# run-batch.sh — run the `sast-driven` engine matrix across the corpus (corpus/pins.jsonl).
#
#   ./run-batch.sh [pins.jsonl] [out-root] [name ...]
#
# Serial by design: each analyze phase already uses 6 cores for cargo, and running two crates at once
# on one box just makes both slower and the timings unusable for the yield ledger.
#
# Its real output is not the findings — it is the cross-crate table at the end. A rule that fires on
# one crate proves nothing; a rule that fires 200 times across six crates and yields no candidate is
# a prune target. THREE crates is the minimum before any prune verdict.
set -u -o pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PINS=${1:-$HERE/pins.jsonl}
OUT_ROOT=${2:-$HOME/rip-sast/results}
shift 2 2>/dev/null || true
ONLY="$*"

command -v jq >/dev/null || { echo "jq required"; exit 1; }
[ -f "$PINS" ] || { echo "no pins file: $PINS"; exit 1; }

echo "=== sast-driven batch: $(date -u +%FT%TZ) ==="
echo "    pins=$PINS  out=$OUT_ROOT  only=${ONLY:-<all>}"

TOTAL=0; OK=0; FAILED=""
while IFS=$'\t' read -r name repo ref; do
  [ -n "$name" ] || continue
  [ "$name" = "null" ] && continue
  if [ -n "$ONLY" ]; then case " $ONLY " in *" $name "*) ;; *) continue ;; esac; fi
  TOTAL=$((TOTAL+1))
  echo
  echo "############ $name ############"
  if "$HERE/sast-scan.sh" "$name" "$repo" "$ref" "$OUT_ROOT"; then
    OK=$((OK+1))
  else
    FAILED="$FAILED $name"
  fi
done < <(jq -r 'select(.name != null) | [.name, .repo, .ref] | @tsv' "$PINS")

echo
echo "=== batch done: $OK/$TOTAL ok${FAILED:+, failed:$FAILED} ==="

# ── the cross-crate yield table — the point of the batch ────────────────────
python3 - "$OUT_ROOT" <<'PY'
import json, sys, pathlib
from collections import Counter, defaultdict

root = pathlib.Path(sys.argv[1])
per_crate, rule_hits, rule_crates = {}, Counter(), defaultdict(set)
group_hits, engine_hits = Counter(), Counter()

for crate_dir in sorted(root.iterdir()):
    if not crate_dir.is_dir():
        continue
    runs = sorted([d for d in crate_dir.iterdir() if (d / "summary.json").exists()])
    if not runs:
        continue
    s = json.load(open(runs[-1] / "summary.json"))
    per_crate[crate_dir.name] = s
    for rule, n in s.get("top_rules", []):
        rule_hits[rule] += n
        rule_crates[rule].add(crate_dir.name)
    for g, n in (s.get("by_clippy_group") or {}).items():
        group_hits[g] += n
    for e, n in (s.get("by_engine") or {}).items():
        engine_hits[e] += n

if not per_crate:
    print("no completed runs found under", root); sys.exit(0)

print("\n=== per-crate volume ===")
print(f"{'crate':<14}{'kLOC':>7}{'raw':>8}{'kept':>8}{'/kloc':>8}{'cells':>7}{'rules':>7}  engines_absent")
for name, s in per_crate.items():
    man = {}
    runs = sorted([d for d in (root / name).iterdir() if (d / "manifest.json").exists()])
    if runs:
        man = json.load(open(runs[-1] / "manifest.json"))
    print(f"{name:<14}{(s.get('loc_non_test') or 0)/1000:>7.1f}{s.get('raw_hits', 0):>8}"
          f"{s.get('kept_hits', 0):>8}{str(s.get('hits_per_kloc')):>8}{s.get('cells', 0):>7}"
          f"{s.get('rules_firing', 0):>7}  {','.join(man.get('engines_absent', [])) or '-'}")

print("\n=== by engine (kept hits, all crates) ===")
for e, n in engine_hits.most_common():
    print(f"  {e:<28}{n:>7}")

if group_hits:
    print("\n=== by clippy group — is pedantic/nursery earning its noise? ===")
    for g, n in group_hits.most_common():
        print(f"  {g:<28}{n:>7}")

print("\n=== top rules by volume (candidates/confirmed are filled in BY HAND after triage) ===")
print(f"{'rule':<52}{'hits':>7}{'crates':>8}   prune-verdict")
for rule, n in rule_hits.most_common(45):
    c = len(rule_crates[rule])
    verdict = "undecided (needs >=3 crates)" if c < 3 else "candidate for DROP if 0 findings"
    print(f"{rule:<52}{n:>7}{c:>8}   {verdict}")
print("\nNOTE: volume alone never prunes a rule. A rule is dropped only after >=3 crates AND zero")
print("candidates that survived verify. Fill the candidates/confirmed columns from /triage output.")
PY
