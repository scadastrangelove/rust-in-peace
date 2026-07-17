# Adding a new target

A target is a directory under `targets/` containing everything the pipeline
needs to build the target and point the find-agent at it. Each target
declares a **profile**:

- `profile: cpp` (the retained base) — builds an ASAN-instrumented binary;
  the oracle is an ASAN abort.
- `profile: rust` (the headline) — builds an ASAN + panic driver and wires
  the multi-detector oracle (Miri / ASan / panic / hang) via
  `run_detectors.sh`. See `targets/rust-canary/` for the reference authoring
  path (`config.yaml` + `Dockerfile` + `run_detectors.sh`).

## Required files

### `config.yaml`

```yaml
profile: cpp                            # cpp (ASAN binary) | rust (Miri/ASan/panic/hang)
image_tag: vuln-pipeline-<name>:latest   # docker tag to build/run
github_url: https://github.com/...      # for the prompt (agent reads source, needs context)
commit: <full-sha>                      # pin exactly what you tested
binary_path: /work/entry                # path INSIDE the container
source_root: /work                      # path INSIDE the container
```

For `profile: rust`, two more fields wire the multi-detector oracle:

```yaml
reattack_harness: /work/run_detectors.sh  # find-agent drives this instead of the bare
                                          # binary; patch re-attack reuses the same oracle
# capabilities.json is auto-detected at targets/<name>/capabilities.json
# (or set capabilities_path: to point elsewhere) — it routes the
# capability-matched cargo-fuzz harnesses.
```

Optional fields:

```yaml
focus_areas:                            # starting points for parallel runs (or use --auto-focus)
  - "PNG chunk parsing (decode_chunk) — IDAT decompression, filter reconstruction"

known_bugs:                             # rendered into the prompt as do-not-resubmit
  - "Crashes in decode_chunk (decoder.h ~4500-4530) — may show as heap-overflow OR assertion. Upstream #123."

attack_surface: |                       # anchors the report-agent's reachability section
  Header-only image decoder library. Real surface: any caller of the public
  load-from-bytes API on untrusted image data. Pure file parser — no wire
  protocol, no auth.

build_command: gcc -O1 -g -fsanitize=address -o /work/entry /work/entry.c
                                        # in-container rebuild for the patch grader (T0).
                                        # Required for `vuln-pipeline patch`; the grader
                                        # applies the diff then runs this to recompile.

test_command: cd /work/src && make check
                                        # regression suite for the patch grader (T2).
                                        # Optional; T2 is skipped if absent.
```

**`known_bugs` format matters.** These go into the find-agent's prompt. Key on
**function name**, not line number — the same bug crashes at different lines
or with different ASAN types (SEGV vs assertion vs stack-overflow) depending on
input. `"null-deref at file.h:1234"` won't match when the agent's crash lands
at `:1240`. Include: crash function, approximate line range, alternate crash
types you've observed.

### `Dockerfile`

Must produce an image where:
- `{binary_path}` is an ASAN-instrumented executable taking one argument (input file)
- `{source_root}` contains the source the agent will read
- `python3`, `xxd`, `file`, `gdb` are available (agent uses these to craft inputs)
- `/bin/bash` works (container entrypoint)

Template (`cpp`):

```dockerfile
FROM gcc:14
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 xxd file gdb && rm -rf /var/lib/apt/lists/*

# COPY source files into /work. Prefer local COPY over git-clone — faster,
# no network in build, pins commit for free.
COPY <your_source_files> /work/

COPY entry.c /work/entry.c
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer -o /work/entry /work/entry.c -lm

CMD ["/bin/bash"]
```

**Flags:** `-O1` per ASAN docs (O0 too slow, O2+ can optimize bugs away).
`-fno-omit-frame-pointer` for readable stack traces.

Template (`rust`) — mirrors `targets/rust-canary/Dockerfile`. Nightly is
required for `-Zsanitizer`, Miri, and `cargo-fuzz`; `rust-src` backs
`-Zbuild-std`:

```dockerfile
FROM rust:1-bookworm
WORKDIR /work
RUN apt-get update && apt-get install -y --no-install-recommends python3 xxd file gdb && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal \
        --component miri --component rust-src --component llvm-tools-preview \
    && rustup default nightly \
    && cargo install cargo-fuzz --locked

COPY crate /work/crate
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/run_detectors.sh

# Fast oracle: the ASAN + panic driver (a `--bin` target, not a C wrapper).
ENV RUST_BACKTRACE=1 ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
RUN cd /work/crate && \
    RUSTFLAGS="-Zsanitizer=address" cargo +nightly build \
        -Zbuild-std --target x86_64-unknown-linux-gnu --bin entry && \
    cp target/x86_64-unknown-linux-gnu/debug/entry /work/entry

CMD ["/bin/bash"]
```

`run_detectors.sh` (referenced by `reattack_harness`) wires the fast driver
plus a `timeout` hang-check and `cargo +nightly miri run` as the deeper UB
oracle; copy `targets/rust-canary/run_detectors.sh` and adapt the crate/bin
names.

### The driver

A thin wrapper: `./entry <input_file>` → run the parser on the file, exit.
Keep it minimal — it defines the attack surface.

- `cpp`: an `entry.c` wrapper compiled with ASAN. The ASAN abort happens
  before `return 0` if there's memory corruption.
- `rust`: a `--bin entry` target in the crate, driven by `run_detectors.sh`.
  The oracle is broader than one abort: Miri UB, a panic-abort (non-zero
  exit), or a hang-timeout each count as a crash. A `reject:` line is
  graceful error handling, not a crash.

## Zero pipeline changes

The pipeline reads `config.yaml` and runs `docker build` on this directory.
No Python edits needed to add a target. Switching stacks is data-only too:
setting `profile: rust` in `config.yaml` (plus a `capabilities.json` and a
`run_detectors.sh` wired via `reattack_harness`) is exactly what selects the
rust prompts and the Miri/panic/hang detectors — no Python changes.
