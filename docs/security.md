# Security considerations

> **TL;DR:** The autonomous pipeline executes target code. Run it via
> `bin/vp-sandboxed`, which confines every agent in a gVisor container with
> egress restricted to the API. Never mount credential-bearing paths into
> the agent's environment. `/threat-model`, `/vuln-scan`, `/triage`, and
> `/quickstart` only read and write files and do **not** need a sandbox.
> `/customize` also edits pipeline source and may run validation
> commands; review its proposed plan before approving.

Frontier models are increasingly good at finding creative paths around
restrictions. The same property that makes them effective vulnerability
hunters also means they may take unexpected actions against their own
execution environment. One team told the model it had no network access,
but it did, so the model fetched from GitHub anyway; another watched an
agent answer a GitHub issue mid-scan. Neither action was malicious, but
both prove the point: models use whatever capabilities you actually give
them, not the capabilities you tell them they have. **Enforce constraints
in code, not in prompts.** It is therefore necessary to run the
model in strong sandboxes and to consider what side effects a process
running in that sandbox could cause. The pipeline ships an agent sandbox: each find/grade/report/recon
agent runs `claude -p` inside a gVisor container with network egress
restricted to `api.anthropic.com:443`, so the agent's `Read`/`Write`/`Bash`
are confined to that container's filesystem and syscall surface.
`scripts/setup_sandbox.sh` installs and verifies it;
[docs/agent-sandbox.md](agent-sandbox.md) covers the architecture and
verification. Agent-spawning subcommands refuse to run outside that sandbox
unless `--dangerously-no-sandbox` is passed.

Concretely, do not run autonomous vulnerability-finding agents in bare
Docker/runc, and especially not with `--privileged` or host networking.
Standard containers share the host kernel, so a kernel exploit inside the
container is a host compromise, and shared-kernel side channels can leak
across containers even without a full escape. Match isolation to the task:
containers are fine for an agent reading code; use a strong isolation layer
such as [gVisor](https://gvisor.dev/), Kata Containers, or
[Firecracker](https://firecracker-microvm.github.io/) microVMs for running
the target, which intercept syscalls or provide a separate guest kernel so
that malicious code has a much smaller attack surface against the host; and
use a separate account and network for anything that detonates exploits. If you're driving the
pipeline interactively from Claude Code on a laptop, rely on the auto-mode
permission classifier and keep a human approving every action that reaches
outside the repo. Never mount credential-bearing paths (`~/.aws`, `~/.ssh`, `.env`,
`~/.kube/config`) into the agent's environment, and do not connect agents to
MCP servers or tools with write access to external state (email, cloud
storage, production infrastructure). For a full treatment of isolation
options, credential proxying, and filesystem hardening, see Anthropic's guide
on [securely deploying AI agents](https://platform.claude.com/docs/en/agent-sdk/secure-deployment).

<a id="setup-attack-isolation"></a>
## Setup → attack isolation phases

Split each run into two phases with different network policy:

- **Setup (network on, ephemeral environment).** The agent pulls
  dependencies, builds the target, installs tools, and stands up its sandbox
  per a spec doc. Run the test suite once to set a baseline, then snapshot
  the result. This phase needs outbound internet but holds nothing worth
  attacking; run it in a disposable account or isolated build environment.
- **Attack (network off, snapshot restored).** Restore the snapshot, hand
  the agent the environment, and lock egress to the model API only via an
  allowlist proxy. The agent can now probe the target with
  `--dangerously-skip-permissions` while anything it triggers, including
  attempts to reach out *through* the target, is contained. Restore the
  snapshot between tries; delete everything when finished.

The proxy doubles as a scope enforcer (only hosts named in the engagement
are reachable), and credentials are scoped per-target so an agent can't
cross-contaminate. Dependencies the agent needs repeatedly get baked into
the setup image so attack-phase runs don't need internet at all. Pin
everything that varies (image tags, commit SHAs, dependency versions, build
commands) so the setup phase is reproducible and the image is the durable
artifact.

`bin/vp-sandboxed` and `scripts/setup_sandbox.sh` are the reference
implementation of this split; see [agent-sandbox.md](agent-sandbox.md).

## Prompt injection

To minimize the risk of prompt injection attacks, avoid providing the model
with untrusted skills, plugins, or MCP servers sourced from the internet.

The pipeline's own agents also read target-derived data: ASAN traces (which
contain function names and file paths from the target's symbol table),
exploitability reports, and build/test output. A malicious target author
could in principle embed instructions in those strings. The find and report
agents have limited blast radius: they run inside a gVisor container on an
internal network with egress restricted to the API, and they produce files
you read. The **patch agent** is the higher-stakes case: its output is
a diff you may apply to a real codebase. The pipeline fences target-derived
text in the patch prompt with per-call random delimiters and instructs the
agent to treat it as data; that's a mitigation, not a guarantee. Review
generated diffs before upstreaming; see
[patching.md](patching.md#reviewing-generated-patches) for what to look for.

**Use `bin/vp-sandboxed` as the entrypoint.** gVisor provides syscall-level
isolation without requiring `/dev/kvm`.
