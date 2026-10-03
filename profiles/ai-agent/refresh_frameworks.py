#!/usr/bin/env python3
"""Resolve the CURRENT version of each framework the ai-agent profile references,
and (optionally) record what this run observed as a provenance lock.

Philosophy: these are evolving standards. We do NOT pin/freeze them. This tool
resolves the current upstream version and lets a campaign RECORD what it saw, so
runs stay reproducible by provenance (a lock file), not by preventing evolution.
A newer upstream than the informational `reference_version` is the expected,
correct state -- not drift to revert.

Read-only toward the network and toward frameworks.json (never edits it). Run
with network access, OUTSIDE the sandboxed finder. stdlib only.

Usage:
  refresh_frameworks.py [--manifest FILE] [--check] [--json] [--lock OUT] [--selftest]
  --check     resolve current versions and print a table (default)
  --json      machine-readable output instead of the table
  --lock OUT  write a provenance lock (resolved versions + date) to OUT
  --selftest  offline checks of manifest shape + verdict logic (no network)
"""
from __future__ import annotations
import argparse, datetime, json, re, sys, urllib.error, urllib.request
from pathlib import Path

_UA = {"User-Agent": "rust-in-peace-ai-agent-framework-refresh/1"}
DEFAULT_MANIFEST = Path(__file__).with_name("frameworks.json")


def _http_get(url: str, accept: str | None = None, timeout: int = 20) -> tuple[int, str]:
    headers = dict(_UA)
    if accept:
        headers["Accept"] = accept
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, resp.read().decode("utf-8", "replace")


def _norm(v):
    return None if v is None else str(v).strip().lstrip("vV")


def resolve_github_release_or_tag(fw: dict) -> str | None:
    repo = fw["repo"]
    try:
        _, body = _http_get(f"https://api.github.com/repos/{repo}/releases/latest",
                            accept="application/vnd.github+json")
        tag = json.loads(body).get("tag_name")
        if tag:
            return tag
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
    except Exception:
        pass
    _, body = _http_get(f"https://api.github.com/repos/{repo}/tags?per_page=1",
                        accept="application/vnd.github+json")
    tags = json.loads(body)
    return tags[0]["name"] if tags else None


def resolve_owasp_year(fw: dict) -> str | None:
    base = int(fw.get("reference_version") or datetime.date.today().year)
    newest = base
    for cand in range(base + 1, base + 4):  # look a few editions ahead
        url = fw["year_url_template"].format(year=cand)
        try:
            status, _ = _http_get(url)
            if status == 200:
                newest = cand
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass
    return str(newest)


def resolve_cwe_homepage(fw: dict) -> str | None:
    try:
        _, body = _http_get(fw["source_url"])
    except Exception:
        return None
    m = (re.search(r"CWE[\s\-]*(?:List\s*)?Version\s*([0-9]+\.[0-9]+)", body, re.I)
         or re.search(r"Version\s*([0-9]+\.[0-9]+)", body))
    return m.group(1) if m else None


_RESOLVERS = {
    "github_release_or_tag": resolve_github_release_or_tag,
    "owasp_year": resolve_owasp_year,
    "cwe_homepage": resolve_cwe_homepage,
}


def verdict(reference, current) -> str:
    if current is None:
        return "unresolved"          # could not reach/parse upstream
    if reference is None:
        return "baseline"            # first observation; nothing to compare
    if _norm(reference) == _norm(current):
        return "current"             # reference matches upstream
    return "evolved"                 # upstream moved on -- expected, use current


def resolve_all(manifest: dict) -> list[dict]:
    rows = []
    for fw in manifest["frameworks"]:
        fn = _RESOLVERS.get(fw["resolver"])
        if fn is None:
            cur, err = None, f"no resolver '{fw['resolver']}'"
        else:
            try:
                cur, err = fn(fw), None
            except Exception as e:  # network/parse failure -> unresolved, not fatal
                cur, err = None, f"{type(e).__name__}: {e}"
        rows.append({
            "id": fw["id"], "name": fw["name"], "resolver": fw["resolver"],
            "reference_version": fw.get("reference_version"),
            "current_version": cur, "verdict": verdict(fw.get("reference_version"), cur),
            "error": err,
        })
    return rows


def _selftest(manifest_path: Path) -> int:
    ok = True
    def check(cond, msg):
        nonlocal ok
        print(("  ok " if cond else "  FAIL ") + msg)
        ok = ok and cond
    print("selftest: manifest shape")
    m = json.loads(manifest_path.read_text())
    check(m.get("schema_version") == 2, "schema_version == 2")
    check(isinstance(m.get("frameworks"), list) and m["frameworks"], "frameworks is non-empty list")
    ids = set()
    for fw in m["frameworks"]:
        for k in ("id", "name", "resolver"):
            check(k in fw, f"{fw.get('id','?')}: has '{k}'")
        check(fw["resolver"] in _RESOLVERS, f"{fw['id']}: resolver '{fw['resolver']}' is known")
        check(fw["id"] not in ids, f"{fw['id']}: id is unique")
        ids.add(fw["id"])
    print("selftest: verdict logic")
    check(verdict("v0.5.1", "v0.5.1") == "current", "equal (v-insensitive) -> current")
    check(verdict("v0.5.1", "0.5.1") == "current", "v-prefix ignored -> current")
    check(verdict("2026", "2027") == "evolved", "newer upstream -> evolved")
    check(verdict(None, "4.17") == "baseline", "no reference -> baseline")
    check(verdict("4.16", None) == "unresolved", "no current -> unresolved")
    print("SELFTEST", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Resolve current framework versions; record provenance.")
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    ap.add_argument("--check", action="store_true", help="resolve + print (default)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--lock", metavar="OUT", help="write a provenance lock JSON to OUT")
    ap.add_argument("--selftest", action="store_true", help="offline checks, no network")
    args = ap.parse_args(argv)
    manifest_path = Path(args.manifest)

    if args.selftest:
        return _selftest(manifest_path)

    manifest = json.loads(manifest_path.read_text())
    rows = resolve_all(manifest)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if args.lock:
        lock = {"generated_at": now, "manifest": str(manifest_path),
                "resolved": {r["id"]: {"current_version": r["current_version"],
                                        "verdict": r["verdict"], "resolver": r["resolver"]}
                             for r in rows}}
        Path(args.lock).write_text(json.dumps(lock, indent=2) + "\n")
        print(f"wrote provenance lock -> {args.lock}")

    if args.json:
        print(json.dumps({"generated_at": now, "frameworks": rows}, indent=2))
    else:
        print(f"framework versions as of {now}  (reference = informational only)\n")
        w = max(len(r["id"]) for r in rows)
        for r in rows:
            note = f"  [{r['error']}]" if r["error"] else ""
            print(f"  {r['id']:<{w}}  reference={str(r['reference_version'] or '-'):<8} "
                  f"current={str(r['current_version'] or '?'):<10} {r['verdict']}{note}")
        evolved = [r['id'] for r in rows if r['verdict'] == 'evolved']
        unresolved = [r['id'] for r in rows if r['verdict'] == 'unresolved']
        print()
        if evolved:
            print(f"  evolved (upstream moved on -- use current, optionally refresh reference_seen): {', '.join(evolved)}")
        if unresolved:
            print(f"  unresolved (could not reach/parse upstream -- recheck later): {', '.join(unresolved)}")
        if not evolved and not unresolved:
            print("  all references match current upstream")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
