# AI and agent systems profile for rust-in-peace

**Status: implementation specification.** `ai-agent` is a proposed additional
profile, alongside `rust`, `cpp`, and the experimental `android-app` profile.
It specializes the existing research workflow for AI applications, agent
runtimes, tools, connectors, and their infrastructure. The current profile
registry does not yet implement `ai-agent`; paths and contracts marked
**proposed** below describe the work required to add it.

The research question is:

> Can an attacker-controlled input, artifact, identity, or sequence of actions
> violate a security invariant of the system in its actual deployment?

The profile supplies useful starting points and verification mechanisms. It is
an **open-ended research direction**: its taxonomy, capability inventory, and
example corpus do not define the complete set of bugs worth finding. A new
mechanism, an ordinary application bug, or a native defect remains a valid
candidate even when no AI-specific category describes it.

The extension follows [G0–G12](extending.md) and the existing
[layer-routing and SAST decisions](DECISIONS.md). Findings still pass through
independent discovery, skeptical triage, reproduction, reporting, and fix
verification. Evidence and lifecycle integration are explicit implementation
work, not guarantees inherited from the experimental APK profile.

## Where the extension belongs

| Layer | Responsibility | Content |
|---|---|---|
| Shared interactive skills | Research method | Threat modeling, independent review, adversarial triage, patch review; select profile context when relevant |
| `profiles/ai-agent/` — proposed | Reusable domain guidance | Scan questions, bounded FP precedents, capability descriptions, framework mappings, adapter contracts |
| `harness/ai_agent/` — proposed | Execution and verification | Profile prompts, scenario drivers, evidence validation, observer adapters, grading and reattack |
| `targets/<target>/` | One concrete assessment | Pinned artifact, deployment configuration, attacker access, fixtures, network policy, budgets |
| Regression corpus | Test the method | Synthetic vulnerable/fixed pairs, decoys, incomplete-evidence cases, separately held-out targets |
| Campaign records | Preserve provenance | Product names, versions, findings, raw observations, disclosure state, experiment statistics |

Skills and reusable profile guidance contain generalized mechanisms and their
conditions of applicability. They do not embed campaign registers, product
names as search hints, known finding IDs, or historical hit-rate claims.
Campaign evidence can justify a new rule without becoming finder context.
Disclosure-sensitive records stay outside public profile documentation.

The same target may expose several layers. An agent service with a native
parser can use both behavioral and native detectors, with evidence attached to
the appropriate finding. Selecting `ai-agent` does not disable other useful
research mechanisms.

## Search directions and security invariants

Start with the target's assets, identities, authority, and deployment. Inspect
source, shipped binaries, configuration, dependency behavior, protocols, and
runtime state as available. Useful directions include:

| Direction | Questions that guide investigation |
|---|---|
| Context and persistent state | Can untrusted documents, retrieved content, tool output, memory, or workspace artifacts acquire authority they should not have? Does influence survive session or tenant boundaries? |
| Identity and authorization | Who can invoke the control plane, change configuration, register tools, access sessions, or use another principal's credentials? Where is that authority enforced? |
| Tools and delegated authority | Can arguments, shell semantics, protocol translation, delegated identities, or composition of individually allowed actions exceed the intended permission? |
| Delayed execution | Can a permitted write or configuration change create an artifact that another component later executes with broader authority? What separate trigger and actor are required? |
| Data and output handling | Can protected data reach another tenant, a response, a log, a file, a tool, or an external recipient? Does downstream interpretation turn output into code or privileged input? |
| Runtime and resource controls | Do effective filesystem, process, network, approval, concurrency, cost, and lifetime constraints match the required policy? Are failures and partial states handled safely? |
| Supply chain and lifecycle | Can an attacker influence dependency resolution, tool metadata, plugins, model artifacts, installers, update trust, or provenance across stages? |
| Observation and accountability | Can actions escape observation, be attributed to the wrong principal, or produce a success claim that hides a security-relevant failure? |

These directions overlap and may be extended during a run. A tool call is one
possible trust boundary; API requests, callbacks, output channels, storage,
loaders, and later consumers are others. The absence of a model invocation does
not disqualify a vulnerability in an AI system.

A policy jailbreak or incorrect answer alone does not establish a security
violation. A protected canary disclosed in a final response does: model text is
an observable output channel. Documented powerful functionality requires an
attacker/authority analysis; neither its danger nor the existence of a risk
acceptance is, by itself, a finding verdict.

Authorization, containment, and the evidence bar constrain execution and
reporting. Taxonomy membership does not constrain discovery.

## Frameworks provide complementary views

| Reference | How to use it |
|---|---|
| [ASAMM taxonomy](https://github.com/scadastrangelove/asamm/blob/main/taxonomy.md) and [environment profile](https://github.com/scadastrangelove/asamm/blob/main/audit/agent-environment-profile.md) | Form questions about context, tool authority, autonomy windows, enabling weaknesses, and assurance controls; record the environment being assessed |
| [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Review risks where a model is a component of an application and communicate their relevance |
| [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Review risks of agents acting through tools, memory, delegation, and workflows |
| [MITRE ATLAS data](https://github.com/mitre-atlas/atlas-data) | Supply adversary-technique hypotheses and report mappings when the observed path supports them |
| CWE | Describe the underlying technical weakness when an applicable class exists |

These are evolving standards: track them rather than pinning them.
`profiles/ai-agent/frameworks.json` lists each source and a resolver, and
`refresh_frameworks.py --lock` records the current version a campaign observed
as a provenance snapshot (reproducibility by record, not by freezing; a newer
upstream is the expected state). Mappings are many-to-many, justified individually, and may
remain unmapped. ASAMM attack paths, enabling weaknesses, and ecosystem
modifiers occupy different fields. C1–C4 are not interchangeable input types.
A technique label is not proof that its prerequisites were met.

Severity comes from demonstrated impact, attacker prerequisites, affected
principals, deployment, and any separate trigger. A Top 10 position, rule
severity, or framework label does not supply the finding's severity. Evidence
certainty and attack reliability are recorded separately from impact.
Framework modifiers inform coordination discussions without automatically
changing a disclosure deadline or claiming downstream production compromise.

## Target contract and capability routing

Each target declares:

- Artifact identity: source commit or binary digest, dependencies, platform,
  shipping build, feature flags, launch configuration, and relevant services.
- Assessment boundary: protected assets, principals, expected invariants,
  attacker-controlled surfaces, and the origin of the policy being tested.
- Runtime mode, state-reset procedure, fixture services, network access,
  credential handling, resource/attempt budgets, and shutdown conditions.
- Available inputs and observers: source, configuration, protocol traffic,
  tool events, process/filesystem observations, and coverage limitations.

A local API is not presumed attacker-reachable from its bind address alone.
Record the deployment and network path. A privileged test client does not
stand in for an unprivileged attacker. For delayed execution, record who causes
the later trigger and under which authority it runs.

**Proposed layout:**

```text
targets/<agent-target>/
  Dockerfile                 # or a declared VM/external test environment
  config.yaml                # future profile: ai-agent selection
  target-contract.json       # artifact, policy, actors, runtime and budgets
  capabilities.json          # observed features with evidence and uncertainty
  fixtures/                  # synthetic accounts, canaries, local services
  driver/                    # real entry-point invocation and state reset
```

The extra files and fields need explicit loader/schema support; copying this
layout does not make the current CLI support the profile.

Capabilities guide tool selection and allocation of effort. Each observation
records `present`, `absent`, `partial`, or `unknown`, with scope, evidence,
collector, and artifact/configuration pin. Absence needs positive justification
within that scope; missing input or a failed scanner is `unknown`. New
capabilities discovered during research update the inventory and may reopen
previously skipped checks.

A gate may skip a **specific engine** when its prerequisite is demonstrably
missing, with a recorded reason. For example, absence of a native artifact can
skip a native detector; it cannot end the review of resource exhaustion. An
unknown capability routes to reconnaissance or general review. An unmapped
capability remains visible and never silently becomes an empty, successful run.
The existing capability loader's vocabulary must be adapted explicitly rather
than silently coercing these states into its current yes/no representation.

## Runtime modes and containment

| Mode | What runs | What the result can establish |
|---|---|---|
| `mechanism` | Real target components or entry points with controlled inputs; recorded or synthetic model responses where needed | Enforcement, protocol, authorization, storage, or lifecycle behavior under the stated inputs |
| `agent_behavior` | A real agent loop consuming attacker-controlled material and choosing actions through an identified model | An observed attack chain for that model, target configuration, state, and trial protocol |

A replayed tool call or model response does not measure whether a live model
would choose it. It can establish a downstream enforcement failure if the
attacker's ability to supply that action is within the declared threat model.
Component-level tests remain useful for research and regression, with their
limited scope retained in the evidence.

Use an isolated local lab with synthetic assets. Offline fixtures are preferred
where they preserve the tested path. Multi-service scenarios may use a private
network with no external egress; a local model or a controlled provider proxy
can support `agent_behavior`. A target that needs a model API is not excluded
by definition. An adapter unable to preserve or observe the required boundary
returns an explicit unsupported/blocked result rather than substituting a
weaker setup and calling it equivalent.

Keep these responsibilities separate:

1. The research agent proposes attack inputs and candidate explanations.
2. The victim runtime executes the tested system with its declared authority.
3. A trusted collector observes effects outside the victim's writable state.
4. A fresh grader verifies the scenario, policy, provenance, and observations.

Separation may use processes, containers, VMs, or an external test environment,
but must preserve the boundary being measured. A container around a sandbox
changes what is observable; record that limitation. Provider credentials and
researcher credentials stay outside victim-controlled processes and files;
only the minimum test identity and synthetic secrets enter the target. The
proxy enforces provider destinations, request budgets, and credential audience.

Treat target files, prompts, tool descriptions, logs, and returned traces as
untrusted data, including when they contain instructions aimed at the grader.
The finder may propose a harness but cannot replace the trusted policy,
observer, or expected result. The grader validates the setup and independently
replays approved inputs in a fresh lab. Persistent state, fixture data, and
external service state must reset as well as the container.

## Evidence contract and promotion

Use a versioned structured evidence bundle for the new profile. The contract
below is **proposed**; it is not the current `SecurityWitness` wire format.
It separates observation, scope, provenance, and verdict instead of deriving
confidence from the cost of instrumentation or the occurrence of a crash.

| Field group | Required content |
|---|---|
| Identity | Schema version, profile, provisional finding/root-cause reference, scenario ID, witness ID |
| Target and policy | Artifact/configuration digests, platform, expected invariant and its policy source |
| Attacker and path | Initial authority, controlled input, actual entry, guard analysis, sink/effect, separate triggers and prerequisites |
| Reproduction | Input bundle and hashes, driver/version, runtime mode, setup/reset steps, budgets and observer configuration |
| Observation | Kind, before/after state or trace references, observed effect, collector identity and trust boundary |
| Scope | `static_path`, `component`, `shipping_entrypoint`, or `full_chain`; substitutions and untested transitions |
| Verification | Independent replay references, control results, evaluator version, disposition and reasons |
| Trials | Attempt IDs, completed/failed trials, observed successes, model metadata when applicable, raw-result references |

Observation kinds can describe filesystem/process effects, network exchanges,
data disclosure (including responses), policy actions, trace assertions,
resource consumption, or native detector output. New bug classes can use these
general mechanisms without a taxonomy addition. A genuinely new evidence kind
is retained as a candidate until a verifier exists; it is not discarded or
silently mapped to a trusted kind.

The AI profile's parser and promotion path must:

- Reject a missing schema, invalid types, unknown required semantics,
  inconsistent references, and unsupported versions as evidence errors.
- Validate evidence paths and bundle extraction; an input bundle must not write
  trusted fixtures, collector state, the oracle, or grader configuration.
- Derive verification status from the trusted evaluator. Finder-provided
  `confirmed`, `strength`, HTTP status, or success strings are claims only.
- Never apply the legacy headerless-output-to-`native_crash` fallback to this
  profile. Compatibility belongs to an explicitly selected legacy format.
- Preserve component-only evidence without inferring a shipping entry point.
- Require observation provenance. A marker created by the PoC itself, an
  invented target log, or a hash-valid trace does not prove victim behavior.

For promotion to a confirmed security finding, the grader establishes the
attacker's access, an actual invariant violation, and a sufficient observed
chain in the declared target configuration. A direct internal call remains
component evidence unless it is itself the supported attacker-facing entry or
is joined to independently established entry-path evidence. Findings that
span later actors or sessions retain those conditions in the verdict.

Run controls appropriate to the mechanism: the authorized operation works,
the malicious variant has a distinguishable effect, and the setup/observer can
detect the expected outcome. An HTTP 200 alone is insufficient. For exfiltration,
observe the protected canary reaching the unauthorized recipient or response;
for a write, observe the victim changing the protected object; for resource
abuse, measure a bounded resource/lifetime violation under the permitted budget.

A complete, authentic trace can support a trace assertion. A missing event
cannot prove that an action was absent without a coverage argument. Log
integrity, event origin, and collection completeness are separate properties.

### Model-dependent trials

Freeze the attack candidate before confirmation and separate discovery attempts
from evaluation trials. Record model identifier/revision when available,
provider/backend, inference settings including seed if supported, context and
memory initialization, tool definitions, target configuration, and resets.
An unavailable value is recorded as unavailable, not invented.

Use a declared trial budget. Report successes/completed evaluable trials,
scheduled attempts, infrastructure failures, and cost; never hide failed trials
by rerunning until success. Matching model and seed is useful metadata, not a
determinism guarantee. One independently witnessed violation can establish an
existence claim; its measured reliability remains explicit. Zero successes in
a finite budget is `not_observed`, not a proof that the target is safe. Changing
the model or attack after evaluation starts creates a new trial series.

## Finding identity and skeptical triage

Keep three identities:

- **Finding:** a root cause and violated security invariant in a component.
- **Attack path:** one way to reach it, including identities, configuration,
  input surfaces, composition, and delayed triggers.
- **Witness:** one observation or reproduction of a path/mechanism.

Deduplication considers root cause, invariant, component, and whether a fix is
independent. Several effects behind one missing guard may be paths of one
finding. Similar entry/sink labels can contain independent defects. Until the
root cause is established, keep provisional candidates rather than merging on
a framework tag or splitting on every endpoint. Preserve path coverage when
findings merge. Report unique causes, attack paths, and witnesses separately.

The skeptic checks correctness, attacker reachability, and impact. Reusable
questions include:

- Does the real entry allow the test input, identity, and state? Did a direct
  call bypass routing, authentication, normalization, or signature checks?
- What do the exact dependency version, API, flags, and downstream guards do?
  One blocked encoding or archive entry does not establish a class-wide defense.
- Does a permitted action become unsafe only after a separate actor, session,
  configuration change, or consumer interprets its output?
- Is the demonstrated behavior a policy violation, an explicitly granted
  capability, an assurance weakness, or an unsupported impact claim? Record
  accepted risk separately from the technical result.
- Does a scanner warning describe actual target code or merely a quoted payload,
  example, test fixture, or unreachable dependency surface?

Refutation requires a reason and evidence. Failure to build, observe, access a
model, or finish within budget leaves the candidate unresolved. Static
observations can be reported as such, including configuration weaknesses;
`confirmed` behavioral impact requires the applicable execution evidence.

## Discovery passes and optional engines

Retain the independent blind, threat-model, and history-seeded passes. Give all
passes the minimum operational facts needed to inspect/run the target. Keep
prior findings, attack hypotheses, framework-guided threat models, and known
answers out of the blind pass. Frameworks enrich questions in guided passes;
they do not filter which candidates may survive.

After triage, an optional **exclusion-frontier** pass receives a minimized map
of already examined mechanisms and unresolved coverage. It looks for variants,
alternative roots, and assumptions worth challenging. The map is a search
prior, not an instruction to accept previous verdicts or ignore adjacent code.
This pass depends on earlier results and is not counted as another independent
vote. Measure its incremental confirmed causes, refutations, and cost on a
separate evaluation set before making it a default.

SAST, event rules, fuzzing, and external probes contribute candidates or
observations. None supplies the final verdict. A disabled optional engine does
not disable general review; an unsupported capability is a visible research
question. Native fuzzing, protocol mutation, argument/encoding variants, and
stateful scenario generation are enabled when they can answer a concrete
question with an executable oracle. The profile does not impose a zero-fuzzing
or zero-memory-corruption assumption.

### Adapter contract

Each adapter declares its role, accepted input modality, prerequisites,
version/ruleset pin, output schema, evidence references, resource needs,
network behavior, licensing constraints, and failure states. Keep engine
failure, unsupported input, no matches, and completed negative tests distinct.
Shared imported rules retain provenance so overlapping scanner output is not
counted as independent evidence.

Candidate integrations, selected per target and measured before expansion:

| Role | Examples | Admission rule |
|---|---|---|
| Inventory | [Agentic Radar](https://github.com/splx-ai/agentic-radar), [AI BOM](https://github.com/cisco-ai-defense/aibom) | Import supported framework/dependency observations with uncertainty; an inventory is not verified reachability |
| Static worklists | [agent-audit](https://github.com/scadastrangelove/agent-audit), [aguara](https://github.com/garagon/aguara), [SkillSpector](https://github.com/NVIDIA/SkillSpector) | Retain file/site and rule provenance; adapt only the target/artifact types the scanner actually supports |
| Typed agent-threat rules | [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) | Honor `scan_target` and field semantics; separate skill/config scanning from model/tool/MCP-event evaluation |
| Effective capabilities | [Sandbox Probe](https://github.com/controlplaneio/sandbox-probe) | Compare observations against the declared policy and deployment baseline; a powerful capability is not automatically a bypass |
| Scenario assertions | [OWASP Agent Security Regression Harness](https://github.com/OWASP/Agent-Security-Regression-Harness) | Reuse applicable drivers/assertions with explicit trace coverage; evaluate live execution separately from replay |
| Observation | [Agentmetry](https://github.com/blitzcrieg1/agentmetry), [Numbat](https://github.com/perplexityai/numbat) | Verify supported sensors, attribution and missing-event behavior; collection or hash integrity alone cannot confirm an attack |
| Artifact inspection and fuzzing | [Fickling](https://github.com/trailofbits/fickling), [ModelScan](https://github.com/protectai/modelscan), [picklescan](https://github.com/mmaitre314/picklescan), [pickle-fuzzer](https://github.com/cisco-ai-defense/pickle-fuzzer) | Scope scanner-bypass claims separately from unsafe artifact loading; run executable verification only inside the target lab |

Start with the smallest adapter set that covers the chosen canary and real
entry points. Add an engine because it supplies missing input coverage or a
useful oracle, not because it increases the tool count. Measure rule hits,
findings discovered while investigating a hit, and duplicates separately.

## Coverage and reporting

A coverage record is bound to artifact, configuration, surface, method, and
budget. Use explicit states:

| State | Meaning |
|---|---|
| `not_present` | Evidence establishes that the prerequisite/surface is absent within the declared scope |
| `not_observed` | The stated tests completed without observing the behavior |
| `not_tested` | No adequate test was performed; include missing input, adapter, model, or budget |
| `blocked_by_control` | A specific attempted path was stopped by an observed control |
| `partial` | Some relevant paths/configurations were examined and others remain |

These states guide future work. They do not assert whole-class immunity, and
new evidence can reopen them. Report source-only candidates, component
reproductions, confirmed findings, refuted candidates, and unresolved work in
separate counts. A zero-finding result includes its coverage and limitations.

Reports name the security invariant, attacker prerequisites, actual entry,
root cause, demonstrated impact, later triggers, evidence scope, reliability,
and fix status. Framework labels are supported metadata. Disclosures follow
the engagement and coordination policy; framework mappings do not independently
authorize publication or a shorter deadline.

## Fix verification and regression corpus

For source-available targets, verify the repaired mechanism through the original
entry and related variants. For binary or externally maintained targets, keep
remediation advice separate from verification on an available fixed artifact.
A successful build, exit code zero, missing crash, or unavailable model is not
an AI-profile fix oracle.

The verification ladder is:

1. Build/launch the candidate fix and validate the environment and observer.
2. Replay the original scenario; the prohibited effect is blocked under the
   same relevant policy and prerequisites.
3. Confirm that the legitimate operation and expected application behavior
   still work; disabling the feature or silently dropping the request is not
   automatically a successful repair.
4. Reattack the mechanism with independent variants, alternate paths, delayed
   consumers, and applicable state/session transitions within the set budget.
5. For model-dependent effects, compare declared trial series and report
   residual successes or insufficient evidence without claiming immunity.

The corpus contains:

- Synthetic vulnerable/fixed pairs and meaningful decoys, including ordinary
  API/authorization defects, context-mediated effects, cross-session state,
  delayed execution, resource limits, and findings outside the initial labels.
- Adversarial evidence cases: forged traces, self-created markers, missing or
  malformed schema, incomplete collection, component-only proof, infrastructure
  failure, and a patch that breaks legitimate functionality.
- A development set for prompt/rule tuning and a separately held-out evaluation
  set. Known historical cases can be regressions without becoming claims of
  fresh discovery or unbiased generalization.
- Pinned real-world artifacts with reviewed per-finding evidence and explicit
  disclosure status. Product-specific data lives in target/campaign records.

Keep answer keys, fixed/vulnerable labels, expected findings, and adjudication
records outside finder mounts and discoverable repository history. Reconcile
source registers before deriving metrics. Publish denominators, dedup units,
verification depth, unresolved cases, and budget. Importing a benchmark requires
checking that its success oracle measures the same claim being evaluated.

## Integration work and delivery gates

The profile should reuse orchestration and artifact storage, with additive,
versioned changes where the current crash contract is insufficient.

| Existing component | Work required for this profile |
|---|---|
| `harness/profiles.py` | Add profile-specific prompt/detector bindings and explicit evidence routing; current `WITNESS:` autodetection points to Android |
| `harness/config.py`, `harness/capabilities.py` | Validate target contract, mode, budgets, feature uncertainty, and adapter prerequisites; preserve existing profile semantics |
| `harness/artifacts.py`, `harness/witness.py` | Introduce/transport strict versioned evidence bundles; keep legacy crash compatibility explicitly scoped |
| `harness/find.py`, `harness/grade.py`, sandbox helpers | Transfer untrusted inputs safely, reset the victim lab, isolate credentials/observer, and verify the real entry; the current one-PoC-file contract needs an adapter |
| Judge, aggregate, dedup and scorecard | Preserve causes/paths/witnesses, verification scope, unresolved outcomes, trial counts, and coverage; consensus cannot promote a candidate by itself |
| Report and report-grader | Use invariant/authority/effect sections and provenance-aware evidence evaluation instead of inheriting a memory-exploitation rubric |
| `harness/patch_grade.py`, reattack routing | Dispatch a behavioral oracle and legitimate-operation controls instead of relying on exit status or sanitizer absence |

**Proposed profile files:**

```text
profiles/ai-agent/
  README.md
  scan-extras.txt
  fp-rules.txt
  capabilities.md
  framework-mapping.md
  adapter-contract.md
  schemas/
    target-contract.schema.json
    evidence.schema.json

harness/ai_agent/
  # find/grade/judge/report/patch prompt builders
  # detector compatibility adapter and strict evidence validator
  # scenario replay, trusted observation, and reattack adapters

targets/ai-agent-canary/
  # synthetic target, drivers and fixtures; answer key held separately
```

Deliver in verifiable stages:

1. **Reusable guidance and contracts.** Generalized scan/triage questions,
   framework mappings, schemas, attack/observation examples, and negative
   controls. Existing interactive skills consume the profile guidance; missing
   runtime verification stays explicitly unresolved.
2. **Mechanism-mode vertical slice.** One canary, one entry-point driver, an
   independent observer, strict evidence validation, fresh grading, dedup,
   reporting, patch checks, and a minimal optional-engine adapter. Register an
   executable profile only when unsupported stages fail explicitly rather than
   falling back to another profile's behavior.
3. **Agent-behavior slice.** Isolated model access, resettable state, trial
   accounting, context-to-effect canaries, and tests against poisoned evidence.
4. **Broader evaluation.** Held-out targets, additional platforms/protocols,
   selected external engines and benchmarks, and measured frontier search.

Before declaring the execution profile usable, demonstrate that:

- A planted vulnerability is confirmed through its real entry; its fixed and
  decoy variants are not mislabeled, and legitimate behavior remains available.
- A forged witness, unsupported schema, incomplete trace, or unavailable
  dependency cannot yield a successful grade or clean scorecard.
- Multiple paths to one defect deduplicate without losing path coverage;
  independent defects with similar entry/sink labels remain distinct.
- An initially unlisted bug class can be discovered and verified; unknown
  capabilities neither terminate search nor produce a false clean result.
- Stateful and delayed effects replay from declared initial conditions, with
  trigger actors and reliability preserved in the report.
- Existing Rust/C++ regression checks retain their results and the APK profile
  retains its declared experimental behavior; compatibility does not import
  permissive evidence defaults into the new profile.

## G0–G12 review checklist

| Gate | Required artifact or decision |
|---|---|
| G0 | Target boundary, assets, attacker access, policy source, actual deployment |
| G1 | Extensible search directions and justified framework mappings |
| G2 | Observation procedure, evidence scope, independent oracle and controls |
| G3 | Pinned target, resettable lab, selected runtime mode and execution limits |
| G4 | Separate root-cause, attack-path and witness identities |
| G5 | Evidence-backed capability inventory with explicit unknowns and reopen rules |
| G6 | Modality-correct optional adapters and strict promotion contract |
| G7 | Independent initial passes; dependent frontier measured separately |
| G8 | Bounded refutation precedents and meaningful decoys |
| G9 | Fail-closed evidence validation, honest unresolved/coverage/trial states |
| G10 | Vulnerable/fixed canaries, provenance-reviewed regressions, held-out evaluation |
| G11 | Existing skills with generalized domain guidance; no campaign answer leakage |
| G12 | Review traces and counterexamples, amend guidance, rerun regressions and evaluate new contributions |

A new finding outside the initial directions is an input to G12, not a reason
to reject it. A new detector or rule earns its place through inspectable
evidence and measured additional value.
