# rust-in-peace target: russcan (a Vectorscan→Rust port). Builds an
# AddressSanitizer driver for the DB-parse + confirm attack surface, plus
# nightly Miri + cargo-fuzz for the detector suite, plus the claude CLI (agents
# run `docker exec … claude -p` inside this image; auth is passed as
# ANTHROPIC_API_KEY at run time).
#
# The russcan source is shipped into the build context as ./russcan-src
# (gitignored — russcan has no public remote). Only the `russcan` facade bin is
# built (-p russcan), so the oracle dev-dependency and the C vectorscan submodule
# are never compiled.
FROM rust:1-bookworm
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 xxd file gdb curl ca-certificates gnupg git \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm i -g @anthropic-ai/claude-code \
    && rm -rf /var/lib/apt/lists/*

# Nightly + the detector components. NB: this rustup wants one --component per
# item (a space-separated list is parsed as extra toolchain names).
RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src \
        --component llvm-tools-preview --component clippy \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

COPY russcan-src /work/russcan
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

# A valid seed DB for the find agent to read + mutate.
RUN cp /work/russcan/crates/russcan/tests/fixtures/realpack.db /work/seed.db 2>/dev/null || true

# Fast oracle: AddressSanitizer driver. A panic unwinds (exit 101); an OOB in
# unsafe → ASAN report. Both are non-zero exits the run harness catches. Only
# the russcan facade bin is built (no oracle dev-dep, no C vectorscan).
ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
RUN cd /work/russcan && \
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly build \
        -Zbuild-std --target x86_64-unknown-linux-gnu -p russcan --bin riptarget && \
    cp target/x86_64-unknown-linux-gnu/debug/riptarget /work/riptarget

# Pre-warm the plain build so `cargo miri run` in the harness is fast.
RUN cd /work/russcan && cargo +nightly build -p russcan --bin riptarget

CMD ["/bin/bash"]
