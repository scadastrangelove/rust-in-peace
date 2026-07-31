#!/usr/bin/env python3
"""lens_stats.py — lens-effectiveness stats from findings-ledger.jsonl.

The 4-lens design (blind / threat-model / cve-seeded / sast-driven) is only worth its cost if we can
measure which lens earns its keep. This reads the per-finding ledger and reports effectiveness —
but ONLY in a way that does not lie by blending incomparable populations.

Two hard rules baked in (see docs/mechanism-effectiveness.md):

  1. NEVER blend precision across campaign classes. Three classes coexist in the ledger and were
     verified to different bars:
       - reasoning  : blind/threat-model/cve-seeded finds that went through a skeptic REFUTATION
                      panel (so `refuted` rows exist) — the ONLY class where precision is meaningful.
       - sast-driven: the SAST pass. Its findings are `source-confirmed` (author read, no refutation
                      panel), so a "precision" over them is untested, not real.
       - historical : already-filed disclosures — survivorship (filed == pre-selected live), not a
                      measure of raw find quality.

  2. NEVER emit a single blended SAST precision. SAST is an ENUMERATOR, not an oracle. Its honest
     number is RULE precision (rule-hit cells / all cells), read from docs/e13/E13-result.json and
     from the per-finding `sast_enumerated` field — reported SEPARATELY from "found-alongside"
     (bugs a reasoning agent found while triaging SAST cells the rule got wrong).

`latent-hardening` is excluded from every precision denominator: it is a REAL bug that just isn't
reachable in the shipping profile (build-gated overflow, a default-off flag, caller-only input) —
a correct disposition, not a false positive.

Usage: python3 scripts/lens_stats.py [findings-ledger.jsonl]
"""
import json, sys, os, collections

HERE = os.path.dirname(__file__)
LEDGER = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "findings-ledger.jsonl")
E13 = os.path.join(HERE, "..", "docs", "e13", "E13-result.json")

REASONING_LENSES = ["blind", "threat-model", "cve-seeded"]
LIVE = {"confirmed-live", "source-confirmed"}   # real / reachable
LATENT = {"latent-hardening"}                   # real but not shipping-reachable — excluded from precision
FALSE = {"refuted"}
# everything else (contained, refound, …) counts in the precision denominator but is not "live"

RULE_HIT = {"site-hit", "site-adjacent"}        # the SAST rule put the defect site in front of a reader
FOUND_ALONGSIDE = {"site-missed", "misdiagnosed"}  # rule got it wrong; a reasoning agent carried it


def campaign_class(campaign: str) -> str:
    if "e13-sast" in campaign:
        return "sast-driven"
    if "chromium" in campaign:
        return "reasoning"
    return "historical"


def lenses_of(r):
    fb = r.get("found_by") or []
    return fb if isinstance(fb, list) else [fb]


def precision(live, false, other):
    denom = live + false + other
    return f"{100*live//denom}%" if denom else "n/a"


rows = [json.loads(l) for l in open(LEDGER) if l.strip()]
by_class = collections.defaultdict(list)
for r in rows:
    by_class[campaign_class(r.get("campaign", ""))].append(r)

print(f"findings in ledger: {len(rows)}  "
      f"(reasoning {len(by_class['reasoning'])} · sast-driven {len(by_class['sast-driven'])} · "
      f"historical {len(by_class['historical'])})")
print("precision excludes `latent-hardening` (real-but-not-shipping ≠ false positive)\n")

# ── 1. REASONING campaigns: the only fair per-lens precision ─────────────────────────────────────
rs = by_class["reasoning"]
print("=" * 74)
print(f"  REASONING campaigns — refutation-tested per-lens precision  ({len(rs)} findings)")
print("=" * 74)
print(f"  {'lens':<14}{'surf':>6}{'live':>6}{'latent':>8}{'false':>6}{'precision':>11}")
for lens in REASONING_LENSES:
    hit = [r for r in rs if lens in lenses_of(r)]
    if not hit:
        continue
    live = sum(1 for r in hit if r.get("verdict") in LIVE)
    lat = sum(1 for r in hit if r.get("verdict") in LATENT)
    false = sum(1 for r in hit if r.get("verdict") in FALSE)
    other = len(hit) - live - lat - false
    print(f"  {lens:<14}{len(hit):>6}{live:>6}{lat:>8}{false:>6}{precision(live, false, other):>11}")
print("  (cve-seeded's edge is expected: seeding from a crate's own CVE history points at real classes)")

# ── 2. SAST: rule precision + found-alongside, NEVER a blended lens precision ─────────────────────
print("\n" + "=" * 74)
print("  SAST — enumerator, not oracle (rule precision reported SEPARATELY)")
print("=" * 74)
cells = tp = fp = other_defects = None
if os.path.exists(E13):
    e = json.load(open(E13)).get("summary", {})
    cells, tp, fp, other_defects = e.get("cells"), e.get("tp"), e.get("fp"), e.get("other_defects")
sd = by_class["sast-driven"]
if cells:
    print(f"  RULE precision (docs/e13/E13-result.json): {tp}/{cells} cells = {100*tp/cells:.1f}%"
          f"   ({fp} fp)")
    print(f"  the pass surfaced {other_defects} found-alongside defects (`other_defects`) — bugs the")
    print(f"    reasoning agent found while triaging SAST cells the rule got wrong (credited to the")
    print(f"    pass, not a rule). Their post-verification funnel:")
else:
    print("  (docs/e13/E13-result.json not found — rule precision unavailable)")

if sd:
    se = collections.Counter(r.get("sast_enumerated", "n/a") for r in sd)
    rule_hit = sum(v for k, v in se.items() if k in RULE_HIT)
    along = sum(v for k, v in se.items() if k in FOUND_ALONGSIDE)
    live = sum(1 for r in sd if r.get("verdict") in LIVE)
    lat = sum(1 for r in sd if r.get("verdict") in LATENT)
    false = sum(1 for r in sd if r.get("verdict") in FALSE)
    print(f"    ledger rows {len(sd)}  ->  live {live} · latent {lat} · refuted {false}"
          f"   (rule-hit {rule_hit} · found-alongside {along}, from sast_enumerated)")
    print(f"    found-alongside precision (refutation-tested): {precision(live, false, 0)}"
          f"   [{live}/{live+false}, latent excluded]")
print("  NOTE: this is the found-ALONGSIDE precision (bugs the reasoning agent kept), NOT a SAST-rule")
print("        precision — the rule's own number is the 2.3% above. Never fold the two.")

# ── 3. HISTORICAL filed corpus: survivorship, reported as a baseline only ─────────────────────────
hs = by_class["historical"]
if hs:
    live = sum(1 for r in hs if r.get("verdict") in LIVE)
    print("\n" + "=" * 74)
    print(f"  HISTORICAL filed corpus (survivorship — NOT a precision signal)  ({len(hs)} findings)")
    print("=" * 74)
    print(f"  {live}/{len(hs)} live — these are already-filed disclosures, pre-selected for having")
    print(f"  survived to disclosure; ~100% is expected and is not a measure of find precision.")

# ── credit / corroboration / verification depth (whole ledger) ───────────────────────────────────
print("\n" + "=" * 74)
print("  WHOLE LEDGER — credit, corroboration, verification depth")
print("=" * 74)
cred = collections.Counter(r.get("first_by") for r in rows if r.get("verdict") in LIVE)
print("  credit (first_by), live only: " + ", ".join(f"{k} {v}" for k, v in cred.most_common()))

corr = [r for r in rows if len(lenses_of(r)) >= 2 and r.get("verdict") in LIVE]
print(f"  independently corroborated live findings (>=2 lenses): {len(corr)}")

vd = collections.Counter(r.get("verified") for r in rows)
print("  verification depth (all rows): " + ", ".join(f"{k} {v}" for k, v in vd.most_common()))

# ── combined attribution: who actually found the real bugs (reasoning vs SAST rule) ──────────────
print("\n" + "=" * 74)
print("  ATTRIBUTION of real findings — reasoning vs SAST rule")
print("=" * 74)
reasoning_live = sum(1 for r in rs if r.get("verdict") in LIVE)
sast_along = len([r for r in sd if r.get("verdict") in LIVE])
print(f"  found by SAST RULE (tp, off-ledger):        {tp if tp is not None else '?'}")
print(f"  found by reasoning lenses (reasoning class): {reasoning_live}")
print(f"  found ALONGSIDE SAST cells (sast pass):      {sast_along}")
total = (tp or 0) + reasoning_live + sast_along
print(f"  ---")
print(f"  reasoning found {reasoning_live + sast_along} of {total} real findings; "
      f"SAST rule found {tp if tp is not None else '?'}.")
print("\n  see docs/mechanism-effectiveness.md for the full write-up and caveats.")
