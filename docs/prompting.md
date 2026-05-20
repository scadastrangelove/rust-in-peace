# Prompting guide

How to prompt Claude for defensive security work. Everything here applies
equally to the system prompt, the first user message, and anything else in
the context window, like CLAUDE.md.

## "Go Find Vulns"

Claude sometimes finds vulnerabilities in ways that would seem alien to a
human researcher, but its approach often works nonetheless. For this reason,
give it high-level tasks (as simple as "find whatever vulnerabilities you can
in this target") and don't prescribe specific ways of working.

## "Go Find Vulns of this Type"

Prompting the model to look for instances of a specific type of vulnerability
that you suspect exists in a codebase can yield good results. Based on prior
vulnerabilities or a codebase's programming language, you may have ideas for
the types of vulns that exist in a given codebase. When telling Claude about
those suspected vulns, you should describe their shape, not checklists. A
prompt that is too specific about the vulnerability limits what the model can
find. Describing the structural properties of a vulnerability works better.
The model already knows f-strings are dangerous. What it doesn't know is that
a dynamic table name in an otherwise parameterized ORM is the same bug.

## Specifying scope

While simple prompts work well for an individual finding agent, it's still
important to divide work cleanly so that parallel agents don't converge to
the same issues and duplicate work. We've found that a recon step that tells
the model precisely what part of the codebase to search over and what to look
for is an effective way to avoid duplication. The recon step is discussed in
more detail in [pipeline.md](pipeline.md).

Claude tends to be exhaustive in what kinds of issues it searches for. If
there are classes of findings that you simply don't care about, it's useful
to prompt the model not to bother spending time on these.

## Share existing mitigations

Tell the model about your own mitigations: if defenses exist in the
architecture that aren't clear from the source code, tell the model about
them to save yourself a lot of noise. If the model is running into tricky
pitfalls that are specific to your environment, it is also worth adding these
to the CLAUDE.md or prompt.

## Order the output schema so thinking precedes scoring

Ask for the bug, the summary, the exploit mechanism, the impact, and *then*
the severity, in that order. If severity comes first, the model anchors on
it and rationalizes backward. Include an explicit escape hatch so the model
can discard a false positive before committing to a score it then has to
defend: "if you cannot construct a path from an entry point to the sink,
mark NOT_EXPLOITABLE and stop."

## Validation and verification

Suggest a way for the agent to verify or validate its work during the
process. Ideally, this is something it can run its solution on that will give
it a clear yes / no answer while it's working. If it's a separate verifier
agent, frame the verifier's task adversarially and put the burden of proof
on the finding. This prompt has worked well in practice:

> You are verifying ONE security finding. Assume it is a FALSE POSITIVE and
> try to disprove it. Read the code and hunt for any reason the finding is
> wrong. Check whether the code is actually reachable and whether
> configurations or defaults prevent exploitation. Only if you genuinely
> cannot find a reason, rule TRUE_POSITIVE.

"Actively look for reasons this is wrong" beats "check for protections."

## Transcript visibility

The model tends to be very token-efficient and sometimes calls lots of tools
without commentary. It can be helpful to prompt the model with some
encouragement like, "Assume that the user can't see most of your tool calls
or your thinking. Give periodic updates when you complete a task or begin a
new one to let the user know what you're doing." This can help you trace the
agent's work, understand where it fails, and tweak your pipeline accordingly.
Your next run of the agent can also learn from the prior run's transcript.

## Preventing harmful actions

The model is extremely effective at working agentically to accomplish a task,
and in some cases has been observed taking potentially harmful actions
without permission. It is possible to reduce this behavior by prompting
Claude to respect certain guardrails. For example, if there are sensitive
credentials on the host machine where Claude is running, it's reasonable to
prompt Claude not to access these credentials.

However, this kind of prompt-based mitigation is not sufficient. We suggest
it only as a defense-in-depth measure. The best approach is to always run
Claude in a secure sandbox environment, or to manually approve all of its
actions. See [security.md](security.md).

## Let Claude write the prompt

Claude can help you write these prompts. Claude wrote most of the prompts in
this pipeline. Feed it these guidelines, describe the task, and ask it to
write the corresponding prompt.
