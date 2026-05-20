# Threat Model: canary

## 1. System context

`canary` is a single-file (~85 LOC) C command-line tool that reads one file
from `argv[1]` into a 4 KB buffer and dispatches to one of three "parser"
functions based on the first byte (`'A'` → `parse_alpha`, `'B'` →
`parse_bravo`, `'C'` → `parse_charlie`). It is built with
`gcc -O1 -fsanitize=address` inside a `gcc:14` Docker image and exists solely
as a fast smoke-test target for the vuln-pipeline; there is no upstream, no
CVE history, and no production deployment. The bugs are deliberately planted
and documented in source comments and `README.md`.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Control of the `entry` process's memory and instruction pointer; in an embedding scenario this is RCE in the caller | critical |
| service availability | Ability of `entry` to terminate cleanly on arbitrary input | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| file input (argv[1]) | `main` (entry.c:64-83) reads up to 4096 bytes from a caller-supplied path and dispatches by `buf[0]` to `parse_alpha` / `parse_bravo` / `parse_charlie` | untrusted file → process memory | host process integrity, service availability |
| build pipeline (Dockerfile) | `FROM gcc:14` pulls a mutable tag from Docker Hub; `apt-get install` pulls unpinned packages | untrusted registry → build artifact | host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory corruption leading to RCE via untrusted file parsing in the alpha/bravo/charlie parsers | local_user | file input (argv[1]) | host process integrity | critical | almost_certain | unmitigated | none | entry.c:25 heap-buffer-overflow (parse_alpha), entry.c:38 stack-buffer-overflow (parse_bravo), entry.c:58 heap-use-after-free (parse_charlie); all documented in README.md |
| T2 | Denial of service via crash or unbounded copy on malformed input | local_user | file input (argv[1]) | service availability | low | almost_certain | risk_accepted | ASAN aborts cleanly; target is a crash-test fixture | entry.c planted bugs (same as T1) |
| T3 | Supply-chain compromise via unpinned `gcc:14` base image or apt packages | supply_chain | build pipeline (Dockerfile) | host process integrity | critical | rare | partially_mitigated | major-version tag pin; image runs `--network none` at runtime | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing | No identity or authentication in scope; input is a file by design |
| Repudiation | No multi-user actions, no audit log, no state |
| Information disclosure | No sensitive data is read or produced |
| Tampering of input at rest | Input file is attacker-supplied by definition; tampering is the attack model, not a separate threat |

## 6. Open questions

- Who supplies the input file in practice? (For the canary itself: the pipeline test harness, so inputs are adversarial by design; for a real target this determines the `actor`.)
- Is the parser ever embedded in a long-lived process, or always invoked as a one-shot CLI? (Determines whether T2 availability impact rises above `low`.)
- Is the Docker build run on a host with broader privileges than the runtime container? (Affects T3 blast radius.)

## 7. Provenance

- mode: bootstrap
- date: 2026-04-21
- target: targets/canary (not a standalone git repo)
- inputs: entry.c source comments + targets/canary/README.md (no --vulns supplied; no git history)
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Bounds-check every input-derived length against the destination buffer before `memcpy` | T1,T2 | partial | S |
| Run all parsers in a sandboxed subprocess (seccomp + `--network none` + memory cap) | T1,T2 | yes | M |
| Pin the Dockerfile base image by digest (`gcc:14@sha256:...`) and apt package versions | T3 | partial | S |
