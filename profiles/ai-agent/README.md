# AI and agent systems research pack

An additional rust-in-peace pack for AI applications, agent runtimes, tools,
connectors and their infrastructure, alongside the Rust and Android packs.

**Status:** interactive review guidance is available, and (2026-10-03) the profile
is **registered as experimental** in `harness/profiles.py` (like `android-app`):
the detector + find/grade/judge/report/patch prompts are wired, config validates the
target contract (fail-closed) for `profile: ai-agent`, and **dynamic confirmation is
now wired** — `grade`/`aggregate` route this profile through the trusted replay
(`runtime.replay` → `evidence.assess`, positive+negative controls); a candidate is
confirmed only by a passed replay, never by "two finders agreed". 70 offline unit
tests pass. It is still **not yet a verified end-to-end run target**: the wired path
has not been exercised through a full `find→…→scorecard` campaign against the live
canary on the host (the grade→replay→assess wired leg is now proven end-to-end on a live target canary on the host — see
IMPLEMENTATION.md), there is no live-agent mode, and a *static* review candidate with
no replay is a *graded candidate*, not a confirmed finding. See
[IMPLEMENTATION.md](IMPLEMENTATION.md) for the remaining steps.

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
The product-specific campaign shortlist is
[AI and agent-system research targets](../../targets/ai-agent-research-targets.md).
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

The profile is registered (experimental) but **not launchable end to end**:
installing the extra enables the offline contracts/replay prototypes and unit tests,
not a verified `vuln-pipeline run`. Container work is paused. If resumed, the
designated execution host is **Tamm = `<redacted-exec-host>`** (`sudo`). Do not
substitute local Docker.
