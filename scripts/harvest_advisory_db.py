#!/usr/bin/env python3
"""W33 — harvest rustsec/advisory-db into a PAIRED TP/TN corpus.

    TP := the crate at the highest version BELOW the patch   (vulnerable)
    TN := the crate at the lowest version WITHIN the patch    (fixed)

The pair is the point. A rule that fires on both is not detecting the vulnerability, it is
detecting the crate's style — a failure mode that is invisible without the pair.
"""
import json, re, sys, os, io, tarfile, pathlib, urllib.request, urllib.error, collections

ADB = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else os.path.expanduser("~/advisory-db"))
OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/rip-corpus"))
LIMIT = int(sys.argv[3]) if len(sys.argv) > 3 else 0

# ── semver, only as much as the patched ranges actually need ────────────────────────────────────
VER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.\-]+))?")

def parse(v):
    m = VER.match(v.strip())
    if not m:
        return None
    maj, mi, pa, pre = int(m[1]), int(m[2]), int(m[3]), m[4]
    # a prerelease sorts BELOW its release; encode with a leading 0/1 flag
    return (maj, mi, pa, 0 if pre else 1, pre or "")

def cmp_ok(v, op, bound):
    a, b = parse(v), parse(bound)
    if a is None or b is None:
        return False
    if op == ">=":  return a >= b
    if op == ">":   return a >  b
    if op == "<":   return a <  b
    if op == "<=":  return a <= b
    if op == "=":   return a[:3] == b[:3]
    if op == "^":   # caret: same left-most non-zero component
        if b[0]: return a[0] == b[0] and a >= b
        if b[1]: return a[0] == 0 and a[1] == b[1] and a >= b
        return a[:3] == b[:3]
    return False

REQ = re.compile(r"(>=|<=|>|<|\^|=)?\s*([0-9][0-9A-Za-z.\-+]*)")

def satisfies(v, req):
    """`req` is one comma-joined conjunction, e.g. '>= 0.2.16' or '>= 1.0, < 1.2'."""
    for part in req.split(","):
        part = part.strip()
        if not part:
            continue
        m = REQ.match(part)
        if not m:
            return False
        if not cmp_ok(v, m[1] or "^", m[2]):
            return False
    return True

def patched_ok(v, ranges):
    """advisory-db `patched` is a LIST of alternatives — any one satisfied means fixed."""
    return any(satisfies(v, r) for r in ranges)

# ── advisory front matter (TOML-ish; only the fields we need) ───────────────────────────────────
def front_matter(text):
    if not text.startswith("```toml"):
        return None
    end = text.find("```", 7)
    return text[7:end] if end > 0 else None

def field(toml, key):
    m = re.search(rf'^\s*{key}\s*=\s*"([^"]*)"', toml, re.M)
    return m[1] if m else None

def listfield(toml, key):
    m = re.search(rf'^\s*{key}\s*=\s*\[([^\]]*)\]', toml, re.M | re.S)
    return re.findall(r'"([^"]*)"', m[1]) if m else []

def load_advisories():
    out = []
    for p in sorted(ADB.glob("crates/*/RUSTSEC-*.md")):
        fm = front_matter(p.read_text(errors="replace"))
        if not fm:
            continue
        pkg = field(fm, "package")
        patched = listfield(fm, "patched")
        if not pkg or not patched:
            continue                                    # no patch => no TN => no pair
        out.append({
            "id": p.stem, "package": pkg, "patched": patched,
            "categories": listfield(fm, "categories"),
            "keywords": listfield(fm, "keywords"),
            "aliases": listfield(fm, "aliases"),
            "informational": field(fm, "informational"),
            "title": next((l[2:].strip() for l in p.read_text(errors="replace").splitlines()
                           if l.startswith("# ")), ""),
        })
    return out

# ── crates.io sparse index + tarball fetch ──────────────────────────────────────────────────────
def index_path(name):
    n = name.lower()
    if len(n) == 1: return f"1/{n}"
    if len(n) == 2: return f"2/{n}"
    if len(n) == 3: return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"

def get(url, binary=False, tries=3):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "rust-in-peace-corpus/1.0"})
            with urllib.request.urlopen(req, timeout=45) as r:
                return r.read() if binary else r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
        except Exception:
            pass
    return None

_versions_cache = {}

def versions(name):
    if name in _versions_cache:
        return _versions_cache[name]
    body = get(f"https://index.crates.io/{index_path(name)}")
    vs = []
    if body:
        for line in body.splitlines():
            if not line.strip():
                continue
            try:
                j = json.loads(line)
            except Exception:
                continue
            if j.get("yanked"):
                continue                                # a yanked TN is not a fix anybody got
            if parse(j["vers"]):
                vs.append(j["vers"])
    _versions_cache[name] = vs
    return vs

def unpack(name, ver, dest):
    if dest.exists() and any(dest.iterdir()):
        return True
    blob = get(f"https://static.crates.io/crates/{name}/{name}-{ver}.crate", binary=True)
    if not blob:
        return False
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as t:
            members = [m for m in t.getmembers()
                       if m.isfile() and ".." not in m.name and not m.name.startswith("/")]
            for m in members:                            # strip the `name-version/` prefix
                m.name = m.name.split("/", 1)[1] if "/" in m.name else m.name
                if m.name:
                    t.extract(m, dest, filter="data")
    except Exception as e:
        print(f"    unpack FAILED {name} {ver}: {e}")
        return False
    return True

def main():
    advs = load_advisories()
    print(f"advisories with a patched range: {len(advs)}")
    OUT.mkdir(parents=True, exist_ok=True)
    manifest, stats = [], collections.Counter()
    for i, a in enumerate(advs):
        if LIMIT and len(manifest) >= LIMIT:
            break
        vs = versions(a["package"])
        if not vs:
            stats["no-index"] += 1
            continue
        fixed = [v for v in vs if patched_ok(v, a["patched"])]
        vuln  = [v for v in vs if not patched_ok(v, a["patched"])]
        if not fixed or not vuln:
            stats["no-pair"] += 1
            continue
        tn = min(fixed, key=parse)
        below = [v for v in vuln if parse(v) < parse(tn)]
        if not below:
            stats["no-pair"] += 1
            continue
        tp = max(below, key=parse)
        d_tp = OUT / "tp" / a["id"]
        d_tn = OUT / "tn" / a["id"]
        if not (unpack(a["package"], tp, d_tp) and unpack(a["package"], tn, d_tn)):
            stats["download-failed"] += 1
            continue
        stats["paired"] += 1
        manifest.append({**a, "tp_version": tp, "tn_version": tn,
                         "tp_dir": str(d_tp), "tn_dir": str(d_tn)})
        if len(manifest) % 25 == 0:
            print(f"  [{len(manifest)}] {a['id']} {a['package']} {tp} -> {tn}")
    (OUT / "manifest.jsonl").write_text("".join(json.dumps(m) + "\n" for m in manifest))
    print("\n=== harvest ===")
    for k, v in stats.most_common():
        print(f"  {k}: {v}")
    print(f"  manifest: {OUT/'manifest.jsonl'}")

if __name__ == "__main__":
    main()
