# Agent sandbox

Each find/grade/report/recon agent runs as `claude -p` *inside* a gVisor
container alongside the target binary and source. The agent's `Read`,
`Write`, and `Bash` tools see only that container's filesystem; gVisor's
userspace kernel intercepts every syscall, so an unexpected agent action is
confined to the guest. The orchestrator (`vuln-pipeline`) stays on the
trusted host and manages container lifecycle, transcript streaming, and PoC
extraction via `docker exec cat`.

## What's isolated

| Surface | Without sandbox | With sandbox |
| --- | --- | --- |
| Agent `Read`/`Write` | host filesystem | container filesystem only |
| Agent `Bash` | host shell | container shell only (gVisor netstack/kernel) |
| Network egress | whatever the host has | `api.anthropic.com:443` only |
| Host coupling | full | `docker exec cat` PoC out, `-v found_bugs.jsonl:ro` in |

**Where each property is enforced:** gVisor provides the syscall and
filesystem boundary (the agent's `Read`/`Write`/`Bash` see only the
container). Egress policy is enforced by docker's `--internal` bridge (no
default route out) plus the allowlist proxy: gVisor's netstack carries the
traffic but the proxy decides what gets through. The verification commands
below demonstrate both.

## Setup (one-time, idempotent)

```bash
./scripts/setup_sandbox.sh
```

Installs `runsc`, registers it as a docker runtime, creates the
`vp-internal` `--internal` network plus the `vp-egress-proxy` allowlist
sidecar, builds the target images and the `+claude` agent layer for each,
and runs the verification checks below. Needs `sudo` for the runtime
install and `/etc/docker/daemon.json`.

**Platform:** gVisor requires a Linux host (x86_64 or aarch64). On macOS or
Windows, run the pipeline inside a Linux VM, or use
`--dangerously-no-sandbox` (plain runc, no syscall isolation; see
[Opting out](#opting-out)).

**Egress allowlist:** the proxy permits `api.anthropic.com:443` only by
default. If you use a non-default `ANTHROPIC_BASE_URL`, set
`VP_EGRESS_ALLOW=host1:443,host2:443` before running `setup_sandbox.sh`; the
script passes it to the proxy container's environment, where
`egress_proxy.py` reads it at startup. Re-run `setup_sandbox.sh` to pick up
a changed value (it recreates the proxy container).

**Pinning gVisor:** `setup_sandbox.sh` downloads a pinned `runsc` release;
override with `RUNSC_RELEASE=<yyyymmdd>` to pin a different one.

## Run

```bash
export ANTHROPIC_API_KEY=...
bin/vp-sandboxed run drlibs --model <model-id> --runs 3 --parallel --stream
```

`bin/vp-sandboxed` checks `runsc` is registered and the proxy is up, sets
`VULN_PIPELINE_AGENT_RUNTIME`/`..._EGRESS_PROXY`/`..._AGENT_NETWORK`, and
execs the pipeline. From there each agent container is spawned with
`--runtime=runsc --network=vp-internal -e HTTPS_PROXY=...`.

## Verifying isolation yourself

```bash
# gVisor active: guest kernel differs from host
docker run --rm --runtime=runsc vuln-pipeline-drlibs-latest-agent:latest uname -r
uname -r

# host filesystem unreachable
echo host > /tmp/probe-$$; \
  docker run --rm --runtime=runsc vuln-pipeline-drlibs-latest-agent:latest cat /tmp/probe-$$

# egress: API reachable, anything else refused
docker run --rm --runtime=runsc --network=vp-internal -e HTTPS_PROXY=http://<proxy-ip>:3128 \
  vuln-pipeline-drlibs-latest-agent:latest sh -c 'curl -sI https://api.anthropic.com/ -o /dev/null -w "%{http_code}\n"'
```

## Opting out

`--dangerously-no-sandbox` skips the sandbox guard. Agents still run in a
container (the prompt expects local paths), but under plain runc with bridge
networking: no syscall interception, full outbound network, and the agent's
credential env var shares that container with the target binary. The
auto-mode permission classifier stays on as the remaining guard. Development
on a throwaway VM only.
