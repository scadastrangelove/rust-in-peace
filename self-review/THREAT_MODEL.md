# Threat Model: rust-in-peace (the pipeline itself)

## 1. System context

rust-in-peace (`vuln-pipeline`, ~11k LOC Python at this repo) is a security tool that finds
vulnerabilities in **untrusted third-party code**. To do that it does two inherently dangerous things:
it **builds and runs untrusted target code** (crashing inputs, fuzzers) inside Docker containers, and it
drives **LLM agents** that **read untrusted target source** and **execute tool calls** (shell, file
ops) while hunting bugs. It forwards a model-API credential (Anthropic API key / OAuth token) to the
agent process, and restricts agent/target network egress through a proxy. The operator runs it on their
own workstation or a build box, often with Docker talking to the host daemon.

The trust boundary is therefore inverted from a normal app: **the input (a target repo + its source +
its built binaries) is actively adversarial**, and the code that processes it is our own orchestration
plus an LLM agent we cannot fully constrain. A compromise means the operator's host / credentials, not
a remote service.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| operator host integrity | The workstation/build box running `vuln-pipeline`; container escape or a host-side command-injection yields code exec at operator privilege | critical |
| model-API credential | `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` (and Bedrock/Vertex creds) forwarded to the agent process — a stealable, billable secret | critical |
| operator data confidentiality | Source, results, transcripts, and anything reachable from the host/containers the run touches | high |
| result integrity | Findings/verdicts reflect reality — a target that can tamper with grading corrupts the security conclusions | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| target source (read by agents) | Find/grade/report agents read the target's files; a malicious repo can embed prompt-injection to steer the agent's tool calls | untrusted repo → agent actions | operator host integrity, model-API credential, operator data |
| target binary (executed) | The crash/fuzz oracle runs attacker-crafted inputs against attacker-influenced builds inside a container | untrusted code → container → host | operator host integrity |
| target `config.yaml` / name / `github_url` / `commit` / paths | Operator-or-repo-supplied strings flow into subprocess argv, docker args, git clone, and filesystem paths | semi-trusted config → host subprocess/FS | operator host integrity, operator data |
| agent → container tool calls | The agent executes shell/file ops inside the container; blast radius depends on the container's isolation, mounts, and env | agent → container | operator host integrity (via escape/mounts), model-API credential (via container env) |
| network egress | Agent/target attempts outbound connections; the egress proxy is the exfiltration control | container → internet | model-API credential, operator data |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Container escape: untrusted target code breaks out of the sandbox to the host | remote_unauth (target author) | executed target binary | operator host integrity | critical | possible | partially_mitigated | gVisor (`runsc`) when enabled; network isolation | depends on default runtime + mounts + caps |
| T2 | Credential theft: untrusted target code (or a prompt-injected agent) reads the forwarded model-API token from the container env / a mount and exfiltrates it | remote_unauth | agent container env, egress | model-API credential | critical | possible | partially_mitigated | egress proxy; separate proxy container holds the token? | needs: is the token in the same container that runs untrusted code? |
| T3 | Prompt injection → the agent performs attacker-directed actions (write host-mounted files, poison results, attempt egress) | remote_unauth | target source read by agent | operator host integrity, result integrity | high | likely | partially_mitigated | untrusted-data wrapping in prompts; sandbox bounds blast radius | agents are told to treat source as data, but they still act on it |
| T4 | Host-side command injection: a target name/URL/commit/path is interpolated into a shell or an argv that reaches a shell (`git clone <url>`, docker args) | remote_unauth | subprocess construction (novelty git clone, docker_ops, agent_image, cli) | operator host integrity | high | possible | partially_mitigated | argv lists (not shell=True) in most call sites | git clone of an attacker `github_url` (`ext::`, `--upload-pack`, submodules) is the classic hole |
| T5 | Egress-proxy bypass → exfiltration of the token / operator data despite the allowlist | remote_unauth | egress_proxy.py allowlist | model-API credential, operator data | high | possible | partially_mitigated | allowlist proxy | DNS rebinding, CONNECT to allowed host then redirect, IP-literal bypass |
| T6 | Path traversal / arbitrary host write: a target name or agent-supplied path escapes `results/`/workspace and writes elsewhere on the host | remote_unauth | results/transcript/poc file writing keyed by target-controlled strings | operator host integrity, operator data | medium | possible | partially_mitigated | fixed output roots | needs: are target names / poc paths sanitized before joining host paths? |
| T7 | Result poisoning: a target detects grading and fakes a pass/fail, or a prompt-injected grader mis-verdicts | remote_unauth | grade/judge over attacker-influenced binary | result integrity | medium | possible | partially_mitigated | fresh container per grade; separate grader | inherent to running attacker code as its own oracle |

Priorities by (impact, likelihood): **T2 (cred theft) and T1 (escape)** are the crown jewels; **T3/T4** are the likely practical vectors.

## 5. Deprioritized

| threat | reason |
|---|---|
| DoS of the pipeline itself (a target that hangs/OOMs a run) | Operator-observable, non-security; the pipeline already bounds turns/time |
| Supply chain of the pipeline's own Python deps | Real but out of scope for this self-review pass (separate audit) |
| Model/agent "jailbreak" producing bad findings | Covered by T3/T7; not a distinct asset compromise |

## 6. Open questions

- Default OCI runtime when `runsc` is absent — does it fall back to `runc` (weak) or refuse?
- Is the model-API token present in the **same** container that executes untrusted target code, or isolated (proxy-only)?
- Are `github_url` / target `name` / poc paths validated before reaching `git clone` / `docker` / host `os.path.join`?
- Does the egress proxy allowlist match on resolved IP or on hostname (rebinding risk)?
- Do any host-side `subprocess` calls ever reach a shell (`shell=True`, or an argv that a tool re-parses)?

## 7. Provenance

- mode: bootstrap (self-review / dogfooding)
- date: 2026-07-18
- target: this repo (`defending-code-reference-harness` / scadastrangelove/rust-in-peace), ~11k LOC Python
- inputs: source read (harness/{sandbox,docker_ops,auth,agent,agent_image,novelty,cli,config}.py, scripts/egress_proxy.py, bin/vp-sandboxed)
- owner: operator (self)

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Keep the model-API token OUT of any container that runs untrusted target code (token only in the proxy/agent-runner, injected per-request) | T2 | yes | M |
| Refuse to run (not silently fall back to `runc`) when the hardened runtime is unavailable, unless an explicit `--dangerously-no-sandbox` flag | T1 | partial | S |
| Validate `github_url` (scheme allowlist https/git, reject `ext::`/`file::`) and use `git -c protocol.ext.allow=never clone --no-recurse-submodules`; sanitize target `name`/paths before any host join | T4,T6 | yes | S |
| Egress proxy: allowlist by resolved IP + re-pin, block IP-literals and redirects to non-allowlisted hosts | T5 | partial | M |
| Keep treating target source as untrusted-data in prompts + bound the agent's writable mounts to the workspace only | T3,T6 | partial | S |

## 9. Target capabilities

Not the standard memory-safety vocabulary — this is a Python orchestration tool, so the relevant shape:
`subprocess_exec` (yes — git/docker), `untrusted_deserialization` (yes — target config.yaml + agent
JSON output), `crypto_secrets` (yes — API token handling), `multi_tenant_authz` (no), `inbound_c_abi`
(no), `unsafe_simd` (no). The oracle here is **appsec code review**, not a crash sanitizer.
