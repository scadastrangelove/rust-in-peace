# `vuln-pipeline-sast` — the sast-driven mode's tool image

The container behind the `/sast-driven` skill. Design: [`../../docs/sast-layer.md`](../../docs/sast-layer.md);
decision record: `docs/DECISIONS.md` **ADR-2**.

**v1 premise: every engine's DEFAULT rules, out of the box — then prune from measured yield.** Not
hand-picked rules: picking up front is guesswork moved earlier. The cost is one noisy first run; the
payoff is a rule set you can defend with a table.

## What's in it

| engine | what it contributes | default rules |
|---|---|---|
| **OpenGrep** 1.26.0 | pattern + taint | upstream `semgrep-rules` (rust + generic) and the trailofbits pack, cloned at build time |
| **ast-grep** 0.45.0 | U1 structural **enumeration** | ours — [`rules/astgrep/`](../../rules/astgrep) (the enumerator + `cls-*` class rules; worklists, not alerts) |
| **clippy** | Rust-native lints | **every** group: `all pedantic nursery cargo` + a curated slice of `restriction` (never the whole group — upstream warns it is deliberately self-contradictory) |
| **Dylint** | type-aware, HIR-level | trailofbits `examples/general`, **pre-built into the image** (`cargo dylint --git` needs network; we run offline) |
| **cargo-audit** | RustSec advisories | advisory-db baked in, `--no-fetch` |
| **cargo-geiger** | unsafe-surface inventory (U1) | n/a — an inventory, not a finder |
| **CodeQL** *(BYOL, opt-in)* | dataflow / taint queries | ours — [`rules/codeql/rust/`](../../rules/codeql/rust) (MIT queries). The proprietary CLI is **never** in the image; mount it via `SAST_CODEQL_CLI` (skill: `--byol codeql`) and it runs as a 7th engine. Off unless `codeql` is in `SAST_ENGINES`. |

Every hit is tagged `engine · rule_id · clippy group · class`. The lint→group table is catalogued at
build time (`lint_catalog.py`) precisely so pruning can be per **group**, not per individual lint.

## Running it

```bash
# one crate
./sast-scan.sh h2 https://github.com/hyperium/h2 9416dc875da6d6b900eedc22636413c62dae912b

# the whole corpus + the cross-crate yield table
./run-batch.sh ../../corpus/pins.jsonl ~/rip-sast/results
```

**Two phases, and the split is the security contract:**

1. **fetch** — network ON, `cargo fetch --locked` only. Cargo resolves and downloads; **no `build.rs`
   and no proc-macro of the target executes.**
2. **analyze** — `--network none`. This is where clippy/dylint compile the crate and therefore *do*
   execute its build scripts, under gVisor when the host registers `runsc`.

Never inverted: nothing that executes target code ever has network. If the host lacks gVisor the
script says so and records `sandbox: docker-default` in `manifest.json` — check that field before
trusting a run on a new host.

## Output

```
<out>/manifest.json    engines ok/absent/failed, image_digest, sandbox, resolved commit
<out>/summary.json     raw→kept, drops by reason, hits/kloc, by engine/class/clippy-group, top rules
<out>/hits.jsonl       normalized hits (engine, rule, class, group, file:line)
<out>/cells.jsonl      clustered (class × module) — THIS is what agents read, never hits.jsonl
<out>/engines.jsonl    per-engine status, rc, seconds
<out>/raw/             untouched tool output (SARIF/JSON) + per-engine stdout/stderr
```

`manifest.json`'s `image_digest` is half the score key `(corpus_rev, image_digest, rule_pack_rev)` —
two runs are only comparable when it matches.

## Two disciplines that are not optional

- **No silent skip.** An engine that is absent, times out, or errors is recorded with its rc and
  stderr tail. A missing engine must never read as "clean". Check `engines_absent` and
  `engines_failed` before quoting any number.
- **A tool hit is never a finding.** `hits.jsonl` → `cells.jsonl` → *a finder agent reads the real
  source* → `F-NNN`. The engines' own severities are advisory and frequently wrong.

## Build

```bash
./build.sh            # base + script overlay, then VERIFY every engine, then write engine-manifest.json
./build.sh --strict   # same, but a missing measurement engine is a hard failure
```

Use the script, not a bare `docker build`. Four of the six engines are installed with
`|| echo "… BUILD FAILED" >> /opt/sast/BUILD-FAILURES.txt` (see the Dockerfile: cargo-audit,
cargo-geiger, cargo-dylint, and the dylint/general prebuild), so a plain build **reports success with
those engines absent** and the only trace is a file nothing reads.

That is not a hypothetical failure mode. Every archived run in `results/` turns out to have fired only
the five `rip-e00*` ast-grep enumerators — no `cls-*` rule ran at all — and conclusions drawn from
those runs were attributed to the method rather than to a five-rule pack. `build.sh` closes that hole:
it executes each engine inside the finished image (presence on `PATH` is not evidence — a dylint
driver that cannot load and a clippy without its SARIF bridge both pass a `which` check and then emit
an empty artifact, which reads as a clean result), prints what the Dockerfile swallowed, and pins the
result in `engine-manifest.json`.

`--strict` exists for measurement runs specifically: comparing a run to an older one is only sound if
both had the same engines, so "we changed the rules" is never confused with "we dropped three
engines".

**Iterating on the scripts:** do NOT rebuild the base for a shell fix — the tool layer costs ~40
minutes of cargo installs. Use the overlay (`./build.sh --overlay-only`, or directly):

```bash
docker build -f Dockerfile.scripts -t vuln-pipeline-sast:v1.3 .
```

It rebuilds in seconds. `run-all.sh` / `normalize.py` are copied **last** in the base Dockerfile, so a
future full rebuild picks up the stabilized scripts without invalidating the tool layers. Bring-up
took three such overlays (v1.1 → v1.3); the defects each fixed are catalogued in
[`../../docs/case-studies/sast-driven-bringup.md`](../../docs/case-studies/sast-driven-bringup.md).

**Known environment requirements**, all learned from real runs and now handled by the scripts:

- **UTF-8 locale is mandatory.** OpenGrep bundles a Python runtime that falls back to the ASCII codec
  and dies on any rule file containing a non-ASCII character. `run-all.sh` exports `LC_ALL=C.UTF-8`.
- **`--metrics` does not exist in OpenGrep** — the fork removed semgrep's telemetry entirely.
- **Dylint needs two things pre-staged**: its per-toolchain *driver*, built during the networked fetch
  phase (it cannot build one offline), and a library directory containing only `.so` files that export
  `dylint_version` — a lint workspace's per-member `.so` files do not, and including them aborts the
  whole run.

Optional engines (geiger, dylint, and the rule-pack clones) may fail without failing the build —
what actually made it in is recorded in `/opt/sast/VERSIONS.txt`, and failures in
`/opt/sast/BUILD-FAILURES.txt`. `run-all.sh` re-checks at run time and reports absences rather than
skipping quietly.

The image is **target-independent** — unlike every other image in this repo, the crate arrives as a
read-only bind mount, so one image serves every target.

## ⚠ Rule-pack licensing — read before pushing this image anywhere

Rule packs are **cloned at build time, never vendored** into this repo. That is not tidiness, it is
the licence:

| pack | licence | what it allows |
|---|---|---|
| `semgrep/semgrep-rules` | **Semgrep Rules License v1.0** — *not* OSI open source | *"You may use the rules only for your own internal business purposes."* · *"This license does not allow you to distribute the rules, or to make them available to others as a service."* |
| `trailofbits/semgrep-rules` | AGPL-3.0 | genuine open source; redistributable under its own terms |

Consequences, and they are load-bearing:

- **Never `docker push` an image built with `INCLUDE_SEMGREP_RULES=1`.** Bundling the rules into an
  image and pushing it is distribution. Such a build stamps `/opt/sast/LICENSE-RESTRICTED.txt`.
- **It is therefore opt-in and OFF by default** (`--build-arg INCLUDE_SEMGREP_RULES=1` to enable), so
  the default image stays distributable.
- **Never vendor those rules into this repo** — it is public and Apache-2.0.
- The cost of the default-off choice is small: the pack contributes **11 Rust rules** (10
  Rust-specific + 1 generic bidi), all shallow audit-tier — hard-coded crypto, disabled TLS
  verification, `unsafe` presence, temp-dir, env/args. Eleven shallow rules do not justify a
  permanent licence encumbrance on the artifact.
- `opengrep/opengrep-rules` is **not** an alternative: it was a fork of semgrep-rules frozen at
  2024-12-13 and **archived in November 2025**. OpenGrep is a live engine with no live independent
  rule registry.
