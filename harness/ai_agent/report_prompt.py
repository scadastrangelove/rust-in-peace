# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
"""report-stage prompt for the ai-agent profile.

Structures the report around the invariant / attacker / entry -> guards -> effect /
evidence-scope, NOT the memory-exploitation rubric. Severity, evidence certainty and
measured reliability are kept as separate fields.
"""
from __future__ import annotations


def build_report_prompt(github_url: str, commit: str, source_root: str, binary_path: str,
                        reproduction_command: str, crash_output: str,
                        attack_surface: str | None, upstream_log: str | None,
                        crash_file: str | None) -> str:
    surface = (attack_surface or "").strip() or "(derive the attack surface from the code)"
    upstream = (upstream_log or "").strip()
    upstream_sec = f"\nUpstream/history context:\n{upstream[:2000]}\n" if upstream else ""
    site = (crash_file or "").strip() or "(component/entry from the AIAGENT header)"
    return f"""Write the exploitability report for this ai-agent finding.

Target: {source_root} (repo {github_url} @ {commit}; artifact {binary_path}).
Candidate / replay entry: {reproduction_command}.
Identity site: {site}
AIAGENT header:
{crash_output}
Attack surface: {surface}{upstream_sec}

Do NOT use the memory-corruption report rubric. Build the report from:
- Component and the security INVARIANT with its policy source (quote it).
- Attacker principal and capabilities; what they were entitled to do.
- Entry -> guards -> effect, each step with an exact path:line and the guard that
  is missing or ineffective.
- Dependencies, configuration and build flags that the claim depends on.
- Separate triggers: any later actor/process/session/user action required, and
  which identity performs it (do not collapse a conditional chain into immediate
  execution).
- Evidence scope: state plainly whether this is a static reachability argument, a
  component-only observation, or a shipping-entry full chain — and what remains
  untested. Dynamic confirmation is the operator's independent replay.
- Three SEPARATE fields: severity (impact + prerequisites), evidence certainty
  (how sure the mechanism is), and measured reliability (only if an independent
  replay produced a rate — otherwise "not measured").

Emit the whole thing inside a single <exploitability_report>...</exploitability_report>
tag. A framework mapping (ASAMM/OWASP/ATLAS/CWE) is optional supporting metadata,
added after the path, and never a substitute for severity or proof."""
