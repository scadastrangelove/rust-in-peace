# AI and agent systems research pack

An additional rust-in-peace pack for AI applications, agent runtimes, tools,
connectors and their infrastructure, alongside the Rust and Android packs.

**Status:** interactive review guidance is available. Execution integration is
paused; `ai-agent` is **not registered** in `harness/profiles.py`. The retained
replay code and canary are prototypes, not a supported `vuln-pipeline run`
target. No container build or end-to-end run has been completed for this pack.

## Use with the existing skills

From the repository root:

```text
/vuln-scan <target-dir> --extra profiles/ai-agent/scan-extras.txt
/triage <findings>.json --repo <target-dir> --fp-rules profiles/ai-agent/fp-rules.txt
```

These are static review and triage instructions; they do not execute the
target. Record candidates, source arguments and unresolved verification needs
honestly. Agreement between reviewers does not establish a reproduced effect.

The guiding question is: can attacker-controlled input, state or a sequence of
actions violate a security invariant in the actual deployment? OWASP, ATLAS,
ASAMM, capability lists and prior cases supply starting points. They do not
limit the set of valid findings. Ordinary authorization, parser, native-code,
resource and lifecycle defects remain in scope.

## Contents

| File | Purpose |
|---|---|
| [scan-extras.txt](scan-extras.txt) | Reusable investigation questions and evidence requirements |
| [fp-rules.txt](fp-rules.txt) | Bounded skeptical-review precedents; no class-wide immunity |
| [capabilities.md](capabilities.md) | Optional-engine routing, uncertainty and reopening decisions |
| [framework-mapping.md](framework-mapping.md) | Justified framework mappings, separate from severity and verdict |
| [frameworks.json](frameworks.json) | Evolving-standard sources + resolvers (tracked, not pinned) |
| [refresh_frameworks.py](refresh_frameworks.py) | Resolve current framework versions and write a per-campaign provenance lock (run with network, outside the find) |
| [adapter-contract.md](adapter-contract.md) | Input modality, provenance, controls and adapter failure states |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Retained code, actual verification status and remaining integration |
| [integration.patch](integration.patch) | Unapplied target-config integration saved for resumption |

The full design is [docs/extending-ai-agents.md](../../docs/extending-ai-agents.md).
Reusable guidance contains generalized mechanisms. Named product findings,
campaign statistics, disclosure records and embargoed material stay in separate
target/campaign records and do not become finder hints.

## Retained execution work

- [harness/ai_agent/](../../harness/ai_agent/): strict JSON contracts, capability
  routing, bounded victim replay and evidence assessment prototypes.
- [Schemas](../../harness/ai_agent/schemas/): versioned scenario, target,
  capability and evidence formats. These are the single schema source; the
  pack does not maintain a divergent copy.
- [targets/ai-agent-canary/](../../targets/ai-agent-canary/): synthetic service,
  trusted target contract and container recipe.
- [Evaluator fixtures](../../tests/fixtures/ai-agent-canary/): attack scenarios
  and a public-operation decoy, kept outside the finder image.

The prototype Python modules require the optional dependency set:

```sh
python -m pip install -e '.[ai-agent]'
```

Installing the extra does not register or launch a profile. Container work is
paused. If resumed, the designated execution host is Tamm, user `gorde`, with
`sudo`; its SSH endpoint still needs resolving. Do not substitute local Docker.
