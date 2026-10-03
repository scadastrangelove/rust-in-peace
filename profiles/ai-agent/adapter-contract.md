# Optional engine and observer adapters

An adapter declares its role, input modality, prerequisites, pinned version and
ruleset, output schema, provenance, resource/network needs, license and failure
states. Inventory, source scanning, event evaluation and execution observations
are distinct roles. A rule written for tool-call events must not silently become
a source-code detector.

Keep `unsupported`, infrastructure failure, no matches and an adequate negative
test separate. Preserve shared-rule provenance across engines; duplicated
rules do not produce independent votes. Scanner hits are candidates, not final
verdicts. Measure direct rule findings, findings encountered during skeptical
investigation and duplicates separately.

Candidate engines and references are listed in the
[design specification](../../docs/extending-ai-agents.md#adapter-contract).
**No external scanner adapter has been integrated by this pack yet.**

Execution verification uses a separate contract:

- The operator pins the target, security policy, principals, entries, controls
  and observation procedure. The finder supplies data, not an executable oracle.
- The victim's credentials, state and model access are isolated from the
  researcher and trusted observer. All target-generated text remains untrusted.
- A fresh lab repeats the frozen scenario and appropriate controls. Preserve
  real entry conditions, later triggers, observer coverage and trial budgets.
- A stub/replay verifies a mechanism. Live agent behavior requires actual model
  use and model/trial metadata. Never relabel one as the other.
- Observed effects must be attributable to the victim and linked to the claimed
  invariant. Hashes provide integrity references, not truth by themselves.
- New evidence types remain candidates until a reviewed verifier is available.

The current prototype supports JSON-stdin entry adapters in a Docker victim
and bounded response/file/exit/duration observations. Model-proxy/live-agent
execution explicitly returns unsupported. Container isolation and these
observers have **not** been exercised end to end; see the implementation ledger.
