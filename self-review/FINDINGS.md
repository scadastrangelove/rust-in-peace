# rust-in-peace self-review — findings (2026-07-18)

Dogfood: ran the union-of-N find + verify pass on the harness itself, seeded by
`self-review/THREAT_MODEL.md`. 13 raw → 11 candidates → **4 confirmed + 1 contested**, each
independently re-verified by reading the code (not trusting the finder agents). These are our own bugs
— fix, don't disclose.

## F1 — model-API credential is in the env of the container that runs untrusted target code  `[T2 · HIGH]`

**Where:** `harness/auth.py:106-111` → `harness/sandbox.py:96-103` (`container_env`) → `harness/docker_ops.py:48-52` (`docker run -e`). Consumed by `find.py`, `grade.py`, `report.py`, `recon.py`, `judge.py`, `rust/find_to_fuzz.py`.

**Taint→sink (verified):** `resolve_auth_env()` returns the raw secret dict
`{ANTHROPIC_API_KEY|CLAUDE_CODE_OAUTH_TOKEN|AWS_BEARER_TOKEN_BEDROCK: <value>}`; `container_env` does
`e = dict(auth or {})` (raw passthrough) and `docker_ops.run` emits `docker run -e ANTHROPIC_API_KEY`,
placing the live credential in the container's `Config.Env`. The find/report/grade prompts direct the
agent to **build and execute the untrusted, attacker-influenced target binary in that same container**
(`find_prompt.py:24,49` — `` `{binary_path} /tmp/your_input` ``). So the attacker's binary (and any
build.rs/test/fuzz script) runs with the credential in its process env (`getenv("ANTHROPIC_API_KEY")`),
and it is visible host-side via `docker inspect`.

**Why the egress proxy doesn't save it:** the proxy allows `api.anthropic.com:443` (the CLI needs it).
In-container code can therefore **use** the stolen key against exactly that host — burn the operator's
credits / drive arbitrary prompts on their account — for the run's duration; TLS is CONNECT-tunneled so
the proxy never strips/injects the token.

**The codebase already knows this is dangerous:** `patch_grade.py:80-97` deliberately runs its T0–T2
target-code containers with `auth=None` + `network="none"` and the comment *"don't put the API
credential in the env of a container running a binary the PoC was crafted to crash."* find/grade/report/
recon/judge do NOT apply that protection — but they can't simply drop the token, because their
in-container `claude -p` authenticates from inside the sandbox.

**Fix (architectural):** don't put the raw token in any container that executes target code. Route the
in-container `claude -p` through the **egress proxy as a credential-injecting reverse proxy** (the proxy
holds the token and adds the `Authorization`/`x-api-key` header to the api.anthropic.com request; the
container env carries only `HTTPS_PROXY`, never the secret). This is mitigation #1 in the threat model.
Interim: at least run the *target-binary-execution* steps in a separate, token-free, `network=none`
container (like patch_grade), separate from the `claude -p` step.

## F2 — soak script runs untrusted target code under runc, as root, with a writable host mount  `[T1 · HIGH]`

**Where:** `scripts/run_fuzz_soak.sh:69,88` (introduced in the P0.3 refill). **Self-inflicted.**

**Trace (verified):** the crate baked into `vuln-pipeline-<profile>-fuzz:latest` is untrusted;
`cargo fuzz run` recompiles it (running its `build.rs`/proc-macros) and executes the harness. The two
`sudo docker run` invocations pass **no `--runtime=runsc`** (so default `runc` — no gVisor syscall
isolation), run as **host root** (`sudo`), mount a **writable** host path `-v "$OUT":/out`
(`$HOME/fuzz-out/...`), and set no `--cap-drop` / `--security-opt=no-new-privileges` / `--user`. The
rest of the pipeline enforces gVisor via `docker_ops.run` + `sandbox.require`; this shell script bypasses
all of it. `setup_sandbox.sh` registers `runsc` only as a *named* runtime (never `default-runtime`), so
the daemon default stays `runc`.

**Fix:** add `--runtime=runsc` (or read `$VULN_PIPELINE_AGENT_RUNTIME`), `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, drop `sudo`/run rootless or `--user`, and make the `/out` mount
read-only where possible (or a scoped, non-`$HOME` dir). Fail closed if runsc is unavailable.

## F3 — no secret redaction when writing agent transcripts/results to the host  `[T2/T3 · HIGH (defense-in-depth)]`

**Where:** `harness/agent.py:280-296` (transcript write), `cli.py` result.json dump. `_truncate_tool_results` (agent.py:87-110) only length-clips to 5000 chars — a ~100-char key survives — and there is **no** redaction/scrub/mask anywhere in the write path (grep confirms).

**Trace:** a prompt-injected agent (steered by untrusted target source, T3) — or a benign `env`/build
dump — can place the credential into a tool_result or assistant message, which is written verbatim to
the host transcript JSONL / result.json under `results/`. Combined with F1 the token is already
in-container, so a dump is easy.

**Fix:** scrub the known secret *values* (the resolved token, from `resolve_auth_env`) from every
message before writing to disk — a single redaction pass over transcript/result serialization.

## F4 — argument injection via unvalidated `commit` into `git log`  `[T4 · MEDIUM]`

**Where:** `harness/novelty.py:50-54`; `commit` loaded raw at `config.py:69` (`commit: str`, no validation).

**Trace (verified):** `subprocess.run(["git","-C",repo_dir,"log","--oneline", f"{commit}..HEAD", "--", repo_path])`.
The `f"{commit}..HEAD"` token is a *revision* argument placed with **no `--`/`--end-of-options` before
it**, so a `commit` beginning with `-` is parsed by git as an **option**, not a revision (leading-dash
argument injection). Depending on the git option this manipulates behavior or, with an output-writing
option, writes a host file at an attacker-influenced path. `commit` is adversary-authored if the target
config.yaml is not fully operator-trusted.

**Fix:** validate `commit` matches `^[0-9a-fA-F]{7,40}$` at config load (`config.py`), and/or pass
`--end-of-options` (or restructure to `git log --oneline "$range" --`) so a leading-dash `commit` can't
be an option. `argv` already avoids a shell, so this is the residual injection vector.

## Contested / not a finding

- **novelty.py `commit` "arbitrary file write" (HIGH claim):** the leading-dash injection is real (F4),
  but the specific `git log --output=<attacker path>` arbitrary-write escalation was not verified (git
  `log` option surface for host writes is narrower than claimed). Kept as F4 (MEDIUM, arg-injection),
  not an arbitrary-write.

## Meta

The pipeline found the exact crown-jewel the threat model flagged (**T2 credential exposure**), plus a
gVisor-bypass I introduced (F2) — a clean dogfood result. F2/F3/F4 are quick fixes; F1 is the
architectural one (credential-injecting proxy).

---

## Fixes applied (2026-07-18)

- **F2 — FIXED** (`scripts/run_fuzz_soak.sh`): both `docker run`s now take `--runtime=runsc`
  (`$VULN_PIPELINE_AGENT_RUNTIME`) + `--cap-drop=ALL` + `--security-opt=no-new-privileges` +
  `--pids-limit`, and **fail closed** if gVisor isn't registered (unless `VP_SOAK_NO_SANDBOX=1`). The
  repro run is additionally `--network=none`. The fuzz-build run keeps network (cargo-fuzz recompiles →
  crates.io); gVisor is its isolation. `bash -n` clean.
- **F3 — FIXED** (`harness/redact.py` + `harness/agent.py`): every transcript line is passed through
  `redact.scrub()`, which replaces live credential values (ANTHROPIC_API_KEY / CLAUDE_CODE_OAUTH_TOKEN /
  AWS_BEARER_TOKEN_BEDROCK / AWS secrets) with a placeholder before hitting disk. Tests:
  `tests/test_redact.py` (4).
- **F4 — FIXED** (`harness/config.py` `_safe_git_ref` + `harness/novelty.py`): `commit` is rejected at
  config load if it starts with `-` / has whitespace / is empty (leading-dash arg-injection guard,
  permissive to hashes AND tags). Bonus: `_ensure_clone` now allowlists the `github_url` scheme
  (rejects `ext::`=RCE / `file::`), passes `-c protocol.ext.allow=never` and `--` before the URL. Tests:
  `tests/test_config_commit_guard.py` (11).
- **F1 — DEFERRED (architectural).** Reading the code confirmed there is no *cheap* split for the
  agent stages: the find/grade/report agent runs the untrusted binary via its own in-container Bash
  (`docker exec X {binary_path}`), so the token-carrying container IS the execution container — splitting
  needs docker.sock-in-agent (worse) or a loop rewrite. Mitigations already present: token is passed as
  `-e KEY` (value from host env, NOT in `docker run` argv → no `ps` leak) and agent mounts are `:ro`;
  residual exposure is in-container `getenv` + `docker inspect`. The real fix is **A — a
  credential-injecting (TLS-terminating) egress proxy**: the token lives only in the proxy, the container
  gets only `HTTPS_PROXY`. Tracked as the follow-up.

**Status: F2/F3/F4 fixed + tested (112 pure tests green, no regression); F1 = design follow-up (A).**
