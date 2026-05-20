# Best practices

General principles for defensive source-code scanning with LLMs. These are
baked into the reference pipeline and the skills in this repo; read this when you
start tuning either for your own stack.

## 1. Map the system before you scan it

On a large codebase, first have Claude read the whole thing and distill a
system design and threat model: how the components fit together, where trust
boundaries sit, what's exposed. Use that map to prioritize which services or
apps to scan first, and run the pipeline component-by-component. Once the
individual pieces are clean, do a pass across the whole system for bugs that
only appear when components chain together. The `/threat-model bootstrap`
skill is built for exactly this first pass.

## 2. Give Claude as much context as you can

Teams have gotten a lot of mileage from pointing Claude at their research
docs, design docs, git history, and even internal portals alongside the
code. The extra context lets Claude connect how components interact and
what's changed over time, which is where the non-obvious bugs live.

Observability data pays off the most. Traces, logs, or a runtime
dependency graph let the model build an architecture map before it starts
hunting, which is where cross-service bugs come from. Injecting a trace ID
and following it through the stack is a cheap way to hand the model that
map.

A common false-positive shape is a real code path that's mitigated one layer
up or down (input validation in a calling service, a sanitizer in a shared
library) and the model flags it because it can't see what it hasn't read.
For internal or upstream code the agent shouldn't have unrestricted access
to, the *wishlist pattern* keeps context curated: give the agent no direct
access, let it return a list of packages or modules it wants to read, a
human provides them, and rerun. The agent pulls exactly what it needs to
rule a finding in or out without you mounting your whole dependency tree.

## 3. Feed it your existing backlog first

Before hunting new bugs, point the model at your current pile of open
findings (older scanners, prior models, bug-bounty intake) and have it
downgrade or disprove what it can. Teams have cleared hundreds of stale
items this way and used the survivors to calibrate severity scoring before
the new findings arrived.

## 4. Divide the work cleanly

Parallel agents converge on the same shallow bugs unless you partition the
search space first. A recon step that tells each agent precisely which part
of the codebase to search, and what to look for, is the most effective way
to avoid duplication. See the pipeline `recon` stage and
[prompting.md](prompting.md) "Specifying scope."

## 5. Prioritize files before the main agent starts searching

Especially when working with large codebases, ask Claude to score files by
the likelihood of having a vulnerability in them before the main agent starts
exploring. Entry points, parsers, anything touching untrusted input rank
high; test fixtures and config noise rank low. This narrows the search space
and keeps early agents on the highest-value surface. However, do not strictly
limit vulnerability searching to a single file; the model is good at
reasoning across files.

## 6. Give the model room to work

Claude is extremely good at finding
vulnerabilities, and it doesn't always go about it the way a human researcher
would. That's fine! The instinct to scaffold the prompt with long
instructions, staged checklists, and piles of reference material usually
backfires. The model ends up pattern-matching against your scaffolding
instead of reasoning about the code. Keep prompts short, give the model
access to tools/Skills you would find useful when doing the task, and step
away.

## 7. Give it a live sandbox, not just source

Source plus a running environment (HTTP traffic, logs, a seeded database, an
emulator) lets the model chain findings into context-aware exploits instead
of stopping at static reports. The deepest results come from teams that let
it execute, observe, and iterate. Static scanning produces hypotheses, not
findings; without a runnable target, the model can't tell a reachable path
from dead code or a real crash from a guarded one, and teams that added a
runnable target watched benign true positives drop to near zero.

Fidelity is the hard part, and two failure modes pull in opposite
directions. A sandbox missing dependencies (queues, datastores, upstream
services) **under-reports**: real bugs don't reproduce. A sandbox that
copies the target but ignores production defenses (WAF, auth gateway)
**over-reports**: bugs production already blocks look live. Don't try to
solve both in the sandbox: let the sandbox answer "is this exploit real,"
and let triage answer "does it matter in production."

Pin everything that varies: image tags, commit SHAs, dependency versions,
build commands. Prefer a local source copy over `git clone` so the build
needs no network. The container image is your durable artifact; the test
loop just consumes cheap resets.

## 8. Separate discovery from verification

These two phases want opposite things, and it's worth framing them
adversarially. Discovery should surface every candidate it can find, even the
speculative ones. Verification should kill anything that isn't actually
exploitable. We learned this the hard way when we asked our discovery agents
to apply strict verification criteria up front, and findings collapsed. The
agents were quietly filtering out things a verifier would have confirmed. So
let discovery be noisy, and run verification as a separate pass whose only
job is to push back.

## 9. Invest in the verifier; it's the load-bearing component

If you only get one piece of the pipeline right, make it the verifier. Teams
new to this work assume prompting is where the payoff is; in practice, the
verifier is where the real engineering happens, and it's what turns a stream
of plausible candidates into a trustworthy queue. Here are some tips to build
an effective agentic verifier:

- Layer a cheap programmatic gate (a sanitizer signal, a parse check, a basic
  validity test) in front of the agentic verifier so most invalid attempts
  are rejected before you spend tokens on them; giving the find agent an
  in-loop oracle it can call against its own candidates also saves iterations
  versus end-of-run grading.
- Per #8 above, run the agentic grader in a clean sandbox the find agent
  never touched: no shared filesystem, environment, or conversation history,
  and don't tell it what the find agent was looking for. Only the artifact
  under test should cross between them.
- Give the grader independent access to the codebase so it actively hunts for
  mitigations the find agent missed; if it can see the find agent's
  reasoning, it tends to be persuaded by it rather than testing the claim.
- Prefer executable witnesses over prose: a PoC that produces an observable
  effect (crash, sanitizer trip, leaked value) is much harder for the
  pipeline to fool itself about than a written argument.

Expect the model to satisfy the verifier rather than find the bug, and harden
against it. The same capability that makes it good at finding vulnerabilities
makes it good at finding the gap between your success criterion and the thing
you actually care about. We've seen agents trigger unrelated assertions or
OOMs when the criterion was simply "the program crashes," use symlink or
path tricks to influence what the grader reads when grader inputs were
writable from the find environment, fabricate plausible ASAN call stacks
using functions the binary never exported, and report vulnerabilities in
stale library versions that the build environment accidentally pulled.
Tighten the criterion until it can only be satisfied by the real thing
(e.g., crash in project code, with a specific sanitizer signature,
reproducing 3/3). Snapshot the target environment before the find agent runs
and grade against the snapshot; no agent-writable path should survive into
grading. Spot-check transcripts where the agent's narration doesn't match
the witness it produced. The only durable defense is an executable oracle:
the PoC fires in a clean sandbox, or it fails. A human reading a convincing
write-up is never enough.

Compound your checks, moving from cheap to expensive: sanity checks (does
the cited code exist, do line numbers match, does the report parse) →
sanitizer signal on the PoC path → an agentic verifier in a fresh container
with independent codebase access → majority vote across several fresh
verifiers, ideally a different model from the finder. Each layer catches
what the cheaper one can't.

## 10. Route verification by vulnerability category

It's best to route verification by the category of vulnerability. For
example, payload-to-sink tracing works for injection and most dataflow bugs
but fails for memory safety. You can spot the unbounded copy from the code,
but exploitability depends on heap layout and mitigations you can't see
statically, so those want a sanitizer run or a reachability argument that
stops short of a PoC. Some bugs are only proven by argument: padding oracles,
auth logic, cases where every step is locally correct and the composition is
wrong. Those go to a single reviewer at a higher bar.

<a id="judge"></a>
## 11. Try using a judge agent to reduce false positives

If you're struggling with false positives, try:

1. A finding agent that generates a bug report
2. A triage agent that writes a critique of the bug report
3. A judge agent that adjudicates between the bug report and the critique

Note that the triage and judge agent should be quite token efficient, as they
only need to consume either the bug report or the corresponding critique.

The same pattern works for severity inflation: run a second-pass skeptical
judge prompted to ask whether the rating is inflated given real-world
exploitability, dead code, test fixtures, or prerequisites that defeat the
conclusion. The model reliably downgrades its own findings when asked this
directly.

## 12. Derive severity from preconditions, not category

Calling every SQL injection a high priority isn't particularly helpful. It's
more honest to have the model list preconditions first and then map from the
count. Zero preconditions and unauthenticated remote access is high priority.
One or two, or an authenticated path, is medium. Three or more, or
local-only, is low. Anchor the scale with a few concrete examples so it
doesn't drift over time.

Models inflate severity for two reasons, and naming them tells you how to
fix it. First, **they don't know what inputs an attacker actually controls.**
A SQL injection is critical if triggered by an unauthenticated request, a
non-issue if triggered by an admin-only config file, and the model can't
always tell by looking at the sink. Second, **they can't see compensating
controls.** The upstream WAF, the auth gateway, the framework default that
escapes output: none of it lives in the scanned code. The fix for both is
the same: provide context that permits a downgrade ("we trust authenticated
clients" removes a whole class of criticals; "this app handles PII" raises
others), and force the model to list preconditions before it assigns a
score.

Even so, treat model-assigned severity as a useful first pass, not ground
truth. It's good enough to order a triage queue, but the model can correctly
identify a vulnerable mechanism while being blind to context that neutralizes
it (a mitigation elsewhere, a reachability constraint, a debug-only path).
Keep a human in the loop for anything rated high or above, and don't gate
automated decisions on the model's self-reported confidence; calibration
varies across model versions on identical evidence.

Verification and triage are independent axes. Verification says "this is
real"; triage says "this is worth your next sprint." Don't let verified
status inflate priority; a confirmed Low is still a Low.

## 13. Find, fix, then find more

If you run the model once, and find+fix N vulns, and then run it again,
you'll likely get more vulns. Increasing parallelism of the initial run
doesn't always lead to more vulns since Claude tends to focus on the same
areas and find duplicates. But doing it iteratively seems to mitigate this
well.

## 14. Expect variance; union across runs

The same prompt on the same target won't return identical findings or
identical severities. Treat each run as a sample: run several, union the
results, and don't trust any single pass. This is the same dynamic
behind #13: iteration surfaces more than parallelism does.

## 15. Start from the running app, not the source dump

Feeding a large codebase up front can make the model less focused. Some have
found it works better to start blackbox (live traffic logs, a Burp/mitm
capture, or just the endpoint inventory) so the model discovers what
actually exists in the deployed app, then reads source as needed. Precision
goes up when the model can tie code paths to real endpoints; "this code
exists" and "this code is reachable in the live application" are different
claims, and the second is the one that matters.

## 16. Provision the right tools

Ripgrep for large source trees, Semgrep for rule-shaped patterns, Ghidra
(CLI or MCP) for binaries, httpx and the project-discovery toolset for web
surface. Or just ask the model what tools it wants for *this* target and
give it one or two; it usually has a sensible answer. Letting it write
small tools of its own is often cheaper and better-fitted than wiring up an
MCP server. Pair the tool with a short skill that says how and when to use
it.

## 17. State the output you want; don't over-structure

"Act like a pentester" is weak. "Produce a findings report with PoC for each
Critical/High, assume there *are* vulnerabilities, and keep going until
you've covered the surface" is stronger: giving the model the end artifact
you expect, and permission to assume the target isn't clean, keeps it from
stopping early.

But there's a balance: too much structure and the model only finds the bug
you pointed at, and the more guardrails you stack on, the more it tends to
work around them. Some have had better luck telling it to chase weird
configurations (the 1% paths) or to rebuild a client from scratch and
notice what breaks, rather than handing it a checklist. Use structure to
*aim*, not to constrain.

Where structure does pay off is in the **output schema**. Order the fields
so the model has to think before it scores: bug → summary → exploit
mechanism → impact → *then* severity. Include an explicit escape hatch
("if you cannot construct a path to the sink, mark NOT_EXPLOITABLE and
stop") so the model can discard a false positive before committing to a
rating it then has to defend.

## 18. For open-source targets, respect the project's threat model

Read the project's published security policy first (often `SECURITY.md`)
and feed it to `/threat-model` as a constraint. Many OSS projects explicitly
scope what counts as a security issue versus expected behavior:
[vLLM](https://docs.vllm.ai/en/latest/usage/security.html), SQLite's
["Defense Against the Dark Arts"](https://www.sqlite.org/security.html),
and [ImageMagick](https://github.com/ImageMagick/ImageMagick/security/policy)
all publish one. Aligning your threat model to that policy up front cuts
findings the maintainers won't accept and keeps the disclosure conversation
productive. This matters more than it used to: AI-generated noise is why
curl [ended its public bug bounty](https://www.bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/)
after the valid-bug rate dropped to 5%. A pipeline that dumps unverified
findings on a maintainer is worse than no pipeline at all. See
[threat-model.md](threat-model.md) for the full treatment.
