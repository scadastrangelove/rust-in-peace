# Rust-security pipeline target image: builds an AddressSanitizer-instrumented
# driver for the vulnerable `rustcanary` crate, plus nightly Miri + cargo-fuzz so
# the run harness can escalate to UB detection and fuzz reproduction.
FROM rust:1-bookworm
WORKDIR /work

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 xxd file gdb \
    && rm -rf /var/lib/apt/lists/*

# Nightly is required for -Zsanitizer, Miri, and cargo-fuzz. rust-src +
# llvm-tools-preview back the sanitizer's -Zbuild-std; miri is the UB oracle.
RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src \
        --component llvm-tools-preview --component clippy \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

COPY crate /work/crate
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

# The fast oracle: AddressSanitizer driver. A panic unwinds → exit 101; an OOB in
# unsafe → ASAN report. Both are non-zero exits the run harness catches.
ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
RUN cd /work/crate && \
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly build \
        -Zbuild-std --target x86_64-unknown-linux-gnu --bin entry && \
    cp target/x86_64-unknown-linux-gnu/debug/entry /work/entry

# Pre-warm a plain (non-sanitizer) build so `cargo miri run` in the harness is
# fast and the T2 regression `cargo test` is ready for the patch grader.
RUN cd /work/crate && cargo +nightly build --bin entry && cargo +nightly test --no-run

CMD ["/bin/bash"]
