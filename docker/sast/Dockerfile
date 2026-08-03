# vuln-pipeline-sast — the `sast-driven` mode's tool image (ADR-2, docs/sast-layer.md §8.3).
#
# TARGET-INDEPENDENT, unlike every other image in this repo: the crate under analysis arrives as a
# read-only bind mount at /src, so one image serves every target. Run it with `--network none` under
# gVisor; deps are pre-fetched host-side (`cargo fetch --locked`) and mounted at /cargo.
#
# Philosophy for v1: EVERY tool's DEFAULT rules, out of the box. Prune later, from measured yield —
# that is what makes the pruning data-driven instead of guesswork. Each hit is tagged with its
# engine + rule + lint-group so pruning can rank by yield per group.
#
# Build robustness: every OPTIONAL engine may fail without failing the build; what actually made it
# in is recorded in /opt/sast/VERSIONS.txt and re-checked at run time by run-all.sh. An engine that
# is absent is REPORTED as absent — never silently skipped.
#
# Rule packs are CLONED at build time, never vendored into this repo: they carry their own licenses
# (semgrep-rules is LGPL-2.1, with Commons Clause on parts) and this repo is Apache-2.0. The image is
# a local build artifact, not a redistributed one.

FROM rust:1-bookworm

ARG OPENGREP_VERSION=1.26.0
ARG ASTGREP_VERSION=0.45.0

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    RUST_BACKTRACE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates jq python3 unzip \
        pkg-config libssl-dev cmake build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/sast /opt/rulepacks /out

# ONLY the build-time helper lands here. run-all.sh and normalize.py are copied at the very END on
# purpose: they change often, and a COPY before the ~40 minutes of cargo installs would invalidate
# the whole cache on every script edit. Iterate on them with Dockerfile.scripts instead.
COPY lint_catalog.py /opt/sast/

# ── engine 1: OpenGrep (pattern + taint) — standalone binary; upstream ships no official image ────
RUN set -eux; \
    curl -fsSL -o /usr/local/bin/opengrep \
      "https://github.com/opengrep/opengrep/releases/download/v${OPENGREP_VERSION}/opengrep_manylinux_x86"; \
    chmod +x /usr/local/bin/opengrep; \
    sha256sum /usr/local/bin/opengrep >> /opt/sast/CHECKSUMS.txt; \
    opengrep --version

# ── engine 2: ast-grep (structural enumeration) — prebuilt; far faster than `cargo install` ───────
RUN set -eux; \
    curl -fsSL -o /tmp/ast-grep.zip \
      "https://github.com/ast-grep/ast-grep/releases/download/${ASTGREP_VERSION}/app-x86_64-unknown-linux-gnu.zip"; \
    sha256sum /tmp/ast-grep.zip >> /opt/sast/CHECKSUMS.txt; \
    unzip -o -j /tmp/ast-grep.zip -d /usr/local/bin; \
    rm -f /tmp/ast-grep.zip; \
    chmod +x /usr/local/bin/ast-grep; \
    ast-grep --version

# ── engine 3: clippy (+ SARIF bridge) ─────────────────────────────────────────────────────────────
RUN rustup component add clippy rustfmt
RUN cargo install clippy-sarif sarif-fmt --locked

# Catalogue every clippy lint and its group, so hits can be tagged by group (correctness / style /
# complexity / perf / pedantic / nursery / restriction / cargo). This is what makes "prune what
# doesn't pay" measurable per GROUP instead of per individual lint.
RUN python3 /opt/sast/lint_catalog.py /opt/sast/clippy-lints.json || \
    echo '{}' > /opt/sast/clippy-lints.json

# ── engine 4: cargo-audit (RustSec advisories) + an offline advisory DB ───────────────────────────
RUN cargo install cargo-audit --locked \
    || echo "cargo-audit: BUILD FAILED" >> /opt/sast/BUILD-FAILURES.txt
# NOT under /root: the analyze phase runs as an arbitrary non-root uid, which cannot even stat
# `/root`, so the copy in run-all.sh silently no-op'd and cargo-audit then failed with
# "failed to read directory /usr/local/cargo/advisory-db/crates". Anything the runtime must read
# lives under /opt/sast, which is world-readable.
RUN git clone --depth 1 https://github.com/RustSec/advisory-db /opt/sast/advisory-db \
    && chmod -R a+rX /opt/sast/advisory-db \
    || echo "advisory-db: NOT FETCHED (cargo-audit will need network)" >> /opt/sast/BUILD-FAILURES.txt

# ── engine 5: cargo-geiger (unsafe-surface inventory — U1 material, not a finder) ─────────────────
# Historically fragile against recent cargo; optional by design.
RUN cargo install cargo-geiger --locked \
    || echo "cargo-geiger: BUILD FAILED (optional)" >> /opt/sast/BUILD-FAILURES.txt

# ── engine 6: Dylint + the trailofbits `general` lint library (type-aware, HIR-level) ─────────────
# The lint libs MUST be pre-built here: `cargo dylint --git` needs network and we run offline.
RUN cargo install cargo-dylint dylint-link --locked \
    || echo "cargo-dylint: BUILD FAILED (optional)" >> /opt/sast/BUILD-FAILURES.txt
RUN set -eux; \
    git clone --depth 1 https://github.com/trailofbits/dylint /opt/rulepacks/dylint || true; \
    if [ -d /opt/rulepacks/dylint/examples/general ] && command -v cargo-dylint >/dev/null; then \
      ( cd /opt/rulepacks/dylint/examples/general \
        && cargo build --release \
        && mkdir -p /opt/sast/dylint-libs \
        && for d in /opt/rulepacks/dylint/target/examples/release \
                    /opt/rulepacks/dylint/examples/general/target/release; do \
             [ -d "$d" ] && find "$d" -maxdepth 1 -name 'lib*@*.so' \
                              -exec cp {} /opt/sast/dylint-libs/ \; ; \
           done; \
        [ -n "$(ls -A /opt/sast/dylint-libs 2>/dev/null)" ] ) \
      || echo "dylint/general: PREBUILD FAILED (optional)" >> /opt/sast/BUILD-FAILURES.txt ; \
    fi
# The lint libs land in the WORKSPACE target dir (`target/examples/release`), not in
# `examples/general/target/release` — cargo hoists them to the workspace root. The original `find`
# looked only in the latter, so `cargo build` reported success, the copy silently found nothing, and
# the image shipped cargo-dylint with an EMPTY library directory: an engine that runs on every crate
# and reports nothing, which is indistinguishable from an engine that ran and found nothing. Both
# paths are searched now, and the `[ -n "$(ls -A …)" ]` turns "copied zero files" into a failure
# instead of a silent pass.

# ── rule packs ────────────────────────────────────────────────────────────────────────────────────
#
# ⚠ LICENSING — semgrep/semgrep-rules is under the **Semgrep Rules License v1.0**, not an OSI licence:
#   "You may use the rules only for your own internal business purposes."
#   "This license does not allow you to distribute the rules, or to make them available to others
#    as a service."
# So an image containing them may be BUILT and USED locally, but **must never be pushed to any
# registry or otherwise shared** — that is distribution. It is therefore OPT-IN and OFF BY DEFAULT:
# the default image stays redistribution-safe, and enabling the pack is a deliberate act that also
# stamps the image as non-distributable (see /opt/sast/LICENSE-RESTRICTED.txt).
#
# The trade is easy: the pack contributes ELEVEN Rust rules (10 Rust-specific + 1 generic bidi), all
# shallow audit-tier — hard-coded crypto, disabled TLS verification, `unsafe` presence, temp-dir,
# env/args. Measured on our corpus they produced almost nothing a Rust reviewer would keep. Eleven
# rules do not justify a permanent licence encumbrance on the artifact.
ARG INCLUDE_SEMGREP_RULES=0
RUN if [ "$INCLUDE_SEMGREP_RULES" = "1" ]; then \
      git clone --depth 1 https://github.com/semgrep/semgrep-rules /opt/rulepacks/semgrep-rules \
        || echo "semgrep-rules: CLONE FAILED" >> /opt/sast/BUILD-FAILURES.txt; \
      printf '%s\n' \
        "This image contains semgrep/semgrep-rules under the Semgrep Rules License v1.0." \
        "Internal use only. DO NOT push this image to any registry, and do not offer it as a" \
        "service. Rebuild with --build-arg INCLUDE_SEMGREP_RULES=0 for a distributable image." \
        > /opt/sast/LICENSE-RESTRICTED.txt; \
    else \
      echo "semgrep-rules: SKIPPED (licence opt-in; --build-arg INCLUDE_SEMGREP_RULES=1)" \
        >> /opt/sast/BUILD-FAILURES.txt; \
    fi
# trailofbits/semgrep-rules is AGPL-3.0 — copyleft, but genuinely open source: it may be
# redistributed under its own terms. One Rust rule (`rs/panic-in-function-returning-result`).
RUN git clone --depth 1 https://github.com/trailofbits/semgrep-rules /opt/rulepacks/trailofbits-semgrep \
    || echo "trailofbits-semgrep: CLONE FAILED" >> /opt/sast/BUILD-FAILURES.txt

# ── writable HOME/cache for an ARBITRARY non-root uid ─────────────────────────────────────────────
# The analyze phase runs `docker run --user "$(id -u):$(id -g)"` (sast-scan.sh) — a uid that does not
# exist in /etc/passwd, so HOME resolves to `/`, which is root-owned. Every tool that writes a cache
# under $HOME then dies. OpenGrep is the loudest: it unpacks its own engine to
# `$HOME/.cache/opengrep/<version>/opengrep.bin` on first use and exits rc=2 with
# "failed to open … for writing" — which the runner records as an engine ERROR, so a whole corpus run
# completes with 0 hits from all 12 opengrep passes and looks like "the tools found nothing".
#
# This was fixed once, in the v1.1→v1.4 overlays during bring-up, and never folded back into this
# base image the way Dockerfile.scripts' own header says it should be. When v1.4 was deleted the fix
# went with it, and the next rebuild silently regressed to the original defect. Keeping it here is
# the fold-back.
#
# Placed late on purpose: it invalidates only the cheap trailing layers, not the ~40-minute tool tier.
ENV HOME=/tmp \
    XDG_CACHE_HOME=/tmp/.cache
RUN mkdir -p /tmp/.cache /.cache && chmod 1777 /tmp /tmp/.cache /.cache

# ── our runner + normalizer, LAST: they change often, everything above does not ───────────────────
COPY run-all.sh normalize.py /opt/sast/
RUN chmod +x /opt/sast/run-all.sh

# ── provenance manifest: what actually made it into this image ────────────────────────────────────
RUN set -eux; \
    { echo "# vuln-pipeline-sast image manifest"; \
      echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"; \
      echo "rustc=$(rustc --version)"; \
      echo "cargo=$(cargo --version)"; \
      echo "clippy=$(cargo clippy --version 2>/dev/null || echo absent)"; \
      echo "opengrep=$(opengrep --version 2>/dev/null || echo absent)"; \
      echo "ast_grep=$(ast-grep --version 2>/dev/null || echo absent)"; \
      echo "cargo_audit=$(cargo audit --version 2>/dev/null || echo absent)"; \
      echo "cargo_geiger=$(cargo geiger --version 2>/dev/null || echo absent)"; \
      echo "cargo_dylint=$(cargo dylint --version 2>/dev/null || echo absent)"; \
      echo "dylint_libs=$(ls /opt/sast/dylint-libs 2>/dev/null | wc -l)"; \
      echo "clippy_lints_catalogued=$(python3 -c 'import json;print(len(json.load(open(\"/opt/sast/clippy-lints.json\"))))' 2>/dev/null || echo 0)"; \
      echo "semgrep_rules_rust=$(find /opt/rulepacks/semgrep-rules/rust -name '*.yaml' 2>/dev/null | wc -l)"; \
      echo "semgrep_rules_total=$(find /opt/rulepacks/semgrep-rules -name '*.yaml' 2>/dev/null | wc -l)"; \
      echo "tob_rules_rust=$(find /opt/rulepacks/trailofbits-semgrep -ipath '*rust*' -name '*.y*ml' 2>/dev/null | wc -l)"; \
    } > /opt/sast/VERSIONS.txt; \
    cat /opt/sast/VERSIONS.txt; \
    echo "--- build failures (empty is good) ---"; \
    cat /opt/sast/BUILD-FAILURES.txt 2>/dev/null || true

# ── LAST: pre-warm and open the caches every root step above just created ────────────────────────
# Setting HOME=/tmp is necessary but NOT sufficient. Every `opengrep --version` executed during the
# build (the install check, and the VERSIONS.txt manifest above) runs as ROOT and unpacks the engine
# into `$HOME/.cache/opengrep/<ver>/` with mode 700. `/tmp/.cache` is sticky (1777), so a non-root
# uid may create its own entries there but cannot write into that root-owned 700 directory — and the
# run fails with exactly the original error, one level deeper.
#
# So do it last, after every root invocation: warm the cache deliberately (the engine is then already
# unpacked and a non-root run only needs to READ it) and relax the modes so any uid can use it.
# `a+rwX` — capital X sets +x on directories only, never on the unpacked payload.
# NOTE it is not only the engine cache. OpenGrep also opens a log at `$HOME/.opengrep/semgrep.log`
# before it does any work, so a chmod covering `.cache` alone still dies — one directory further in,
# with the same Errno 13. Everything the build put under HOME is opened, not an enumerated subset.
# `/work` is the same defect a third time. run-all.sh copies the read-only `/src` mount into a
# WRITABLE `/work` (clippy and dylint must compile the crate, which a `:ro` mount cannot support), and
# creating a directory at `/` is exactly what an arbitrary uid cannot do — so the copy fails, every
# engine then runs against a path that does not exist, and the crate reports 0 hits from 12 engines.
# Pre-create it here; the runtime cannot.
# `/w` is the FETCH phase's staging copy (sast-scan.sh), and it needs the same treatment as `/work`:
# that phase also runs `--user "$(id -u):$(id -g)"`, so its `cp -a /src /w` failed with the same
# Permission denied — meaning `cargo fetch` never ran, no Cargo.lock was ever resolved, and the
# Dylint driver was never warmed. Every downstream symptom (audit "absent", geiger reaching for
# index.crates.io, dylint rebuilding its driver offline) traced back here.
RUN opengrep --version >/dev/null 2>&1 || true; \
    mkdir -p /tmp/.cache /tmp/.opengrep /.cache /work /w; \
    chmod -R a+rwX /tmp /.cache; chmod 1777 /work /w; \
    ls -ld /tmp/.cache/opengrep /tmp/.opengrep /work /w 2>/dev/null || true

WORKDIR /src
CMD ["/opt/sast/run-all.sh"]
