# Frameworks are complementary research views

| Reference | Use |
|---|---|
| [ASAMM taxonomy](https://github.com/scadastrangelove/asamm/blob/main/taxonomy.md) | Questions about context, tool authority, autonomy, enabling weaknesses and assurance controls |
| [ASAMM environment profile](https://github.com/scadastrangelove/asamm/blob/main/audit/agent-environment-profile.md) | Deployment assumptions and the assessed environment |
| [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) | Application risks involving models |
| [OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) | Tools, memory, delegation and autonomous workflows |
| [MITRE ATLAS data](https://github.com/mitre-atlas/atlas-data) | Adversary-technique hypotheses and evidenced attack paths |
| [CWE](https://cwe.mitre.org/) | Underlying technical weaknesses |

These are **evolving** standards — track them, do not freeze them.
[`frameworks.json`](frameworks.json) lists each one's canonical source and a
resolver; [`refresh_frameworks.py`](refresh_frameworks.py) resolves the current
version and, with `--lock`, writes a per-campaign provenance snapshot. Use the
current version; reproducibility comes from **recording what a run observed**
(the lock), not from pinning. A newer upstream than the informational
`reference_version` is the expected, correct state. Run `refresh_frameworks.py`
with network access, outside the sandboxed finder.

Mappings may be many-to-many or absent. Include a justification per mapping.
Keep ASAMM attack paths, enabling weaknesses and ecosystem modifiers separate;
do not force every finding into a context-injection category. Framework ranking
does not determine severity, prove reachability or set a disclosure deadline.

Severity describes actual impact and prerequisites. Evidence certainty and
measured attack reliability are different fields. A newly discovered mechanism
without a suitable label is input to further research, not a rejected finding.
