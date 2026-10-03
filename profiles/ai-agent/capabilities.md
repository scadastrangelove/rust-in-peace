# Capabilities guide optional engines

Record capabilities with a pinned artifact/configuration, scope, collector and
evidence. The pack uses `present`, `absent`, `partial`, `unknown`; it does not
coerce them into the legacy Rust/APK `yes/no/test_only/partial` vocabulary.

| State | Meaning and routing |
|---|---|
| `present` | Evidence supports a prerequisite; consider the applicable engine |
| `absent` | Evidence establishes absence within a stated scope; skip only that engine |
| `partial` | Some relevant paths are known; investigate the remainder |
| `unknown` | Missing or inconclusive information; reconnaissance/general review remains active |

The inventory is extensible. Missing keys mean unknown; unmapped keys become
research work. Even an empty inventory retains general review. New evidence
reopens earlier skips. A native detector may be inapplicable while resource,
protocol or application-level investigations continue.

Example directions include persistent context, multi-tenant state, delegated
identity, tools, delayed consumers, network protocols, native parsers, model
artifacts and external observation. This is not a closed list.

The prototype [Inventory](../../harness/ai_agent/capabilities.py) returns
`run`, `investigate` or `skip` per engine and its declared prerequisites.
It does not launch scanners or connect to the general pipeline's routing yet.
The [JSON schema](../../harness/ai_agent/schemas/capabilities.schema.json)
requires evidence for present/absent observations.
