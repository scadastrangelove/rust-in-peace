FROM rust:1-bookworm
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 xxd file gdb \
    && rm -rf /var/lib/apt/lists/*
RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src --component llvm-tools-preview --component clippy \
    && rustup default nightly && cargo install cargo-fuzz --locked
COPY parser /work/parser
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh
ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
RUN cd /work/parser && RUSTFLAGS="-Zsanitizer=address" cargo +nightly build \
        -Zbuild-std --target x86_64-unknown-linux-gnu --bin riptarget \
    && cp target/x86_64-unknown-linux-gnu/debug/riptarget /work/riptarget
RUN cd /work/parser && cargo +nightly build --bin riptarget
CMD ["/bin/bash"]
