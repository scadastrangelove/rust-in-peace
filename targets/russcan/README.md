# russcan — rust-in-peace target

[russcan](https://github.com/anthropics) is a Vectorscan→Rust port (a
multi-literal / regex matcher). This target points the `rust` profile at its
DB-parse + confirm attack surface.

- **Attack surface:** `russcan::Database::load(bytes)` then `scan_block` on a
  fixed buffer — driven by an untrusted serialized vectorscan DB (the input
  file). The `riptarget` driver (`crates/russcan/src/bin/riptarget.rs`) is the
  entry point.
- **Detectors:** AddressSanitizer (real AVX2/NEON unsafe SIMD reads), Miri
  (scalar backend — confirm-path unchecked reads), hang-timeout, cargo-fuzz.
- **What a run checks:** russcan was recently hardened (parse-time
  `validate_confirm`, fallible Rose operand reads, an instruction budget, NFA
  parse guards). A clean run confirms the hardening holds against a hostile
  CRC-valid DB; a crash finds a gap.

## Build context

russcan has no public remote, so its source is shipped into `russcan-src/`
(gitignored) before `docker build`:

```bash
# from a machine with the russcan checkout:
rsync -a --exclude target --exclude 'build-*' --exclude vectorscan \
      /path/to/russcan/ targets/russcan/russcan-src/
sudo docker build -t vuln-pipeline-russcan:latest targets/russcan
```

## Run (needs Anthropic auth on the host)

The agents run `docker exec … claude -p` inside the image; auth is passed as
`ANTHROPIC_API_KEY` at run time. No gVisor here → use the sandbox override.

```bash
export ANTHROPIC_API_KEY=…            # your key, on the host
python -m harness.cli run targets/russcan --dangerously-no-sandbox   # or bin/vp-sandboxed
```
