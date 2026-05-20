# Other security tasks

The skills and reference pipeline in this repo focus on finding vulnerabilities in
source code. The model performs well on a number of other defensive security tasks. This list
is not exhaustive; please experiment, and tell us what works. Keep
[security.md](security.md) in mind as you do.

## Vulnerability patching

* We've seen success using Claude to deliver vulnerability patches. Start
  with your default Claude Code model; move to a more capable model if patches
  are insufficient.
* Ensure you have good tests to prevent regressions and confirm the patch
  solved the issue; use Claude Code to help write them.
* Give the model details on the vulnerability and a way to verify the patch
  (e.g., ability to build and/or run tests). Then trust it to do the right
  thing.
* Claude is great at variant analysis and making sure a patch is complete,
  but you have to tell it to do this. If you don't explicitly prompt it to be
  thorough and patch variants, it won't.

## Bug chain analysis

* If you have a backlog of known bugs, point the model at it and ask which
  ones chain together for greater impact.
* Individually low-/medium-severity bugs can compose into a critical issue,
  and the model is effective at spotting these chains across a backlog a human
  triaging one ticket at a time would miss.
* This can help you prioritize the bugs in your backlog.

## Threat intelligence

* See our cookbook
  (https://platform.claude.com/cookbook/tool-use-threat-intel-enrichment-agent)
  for an end-to-end threat intelligence agent that autonomously investigates
  IOCs: queries multiple threat-intel sources, cross-references findings,
  maps to MITRE ATT&CK, and produces structured reports for SIEM/SOAR
  integration.
