# Threat model: decide what counts before you look

The most common cause of false positives isn't the model misreading code;
it's the model lacking your trust boundaries. Claude flags a bug because it
assumes a client sends bad values or an attacker controls a config file. The
code read is correct; the threat model is wrong. A bug is only a
vulnerability relative to what you choose to defend against, and if you
don't write that decision down, the model guesses, and guesses high.

The threat model scopes everything downstream:

- It tells the **sandbox** which services must actually run versus stay
  read-only.
- It tells **discovery** where to look and what to skip.
- It gives **verification** a standard: does this finding achieve a scenario
  we care about?
- It gives **triage** the assets at stake, so severity is grounded in your
  system instead of a generic rubric.

## Two ways to build one (use both)

**Bootstrap from the code.** Feed Claude what you'd hand a new security
engineer on day one: architecture docs, wikis, entry points, git history,
and past CVEs. Models cannot infer implicit knowledge from code alone; the
gap between what lives in the code and what lives in the wiki is where
benign true positives come from. Ask Claude to map trust boundaries and
cluster past bugs by class. The output is a draft list of what's reachable,
what handles untrusted input, and what historically breaks. `/threat-model
bootstrap` is built for this.

**Interview the owner.** Walk a system expert through Shostack's four
questions: What are we building? What can go wrong? What are we doing about
it? Did we do a good job? Run the bootstrap step first so the owner reviews
a draft rather than starting from a blank page. This cuts their time from
hours to a review pass, which is the difference between getting a threat
model and not getting one. `/threat-model bootstrap-then-interview` does
exactly this.

## Practices that make the biggest difference

- **Treat the project's security policy as ground truth.** Many OSS projects
  publish one: [vLLM's `docs/usage/security.md`](https://docs.vllm.ai/en/latest/usage/security.html),
  SQLite's ["Defense Against the Dark Arts"](https://www.sqlite.org/security.html),
  [ImageMagick's security policy](https://github.com/ImageMagick/ImageMagick/security/policy).
  These document what's in and out of scope. Your threat model should ingest
  those rules, not rediscover them.
- **Mine your history.** Look past known exploits to past git commits. Find
  what the team fixed, with or without an exploit. Past fixes map where bugs
  live and predict where the next ones surface.
- **Name what is trusted.** If you trust config files, authenticated
  clients, or a particular internal service, say so explicitly. These
  assumptions are what separate a real exploit from a benign true positive,
  and they're the difference between ten real bugs and two hundred noisy
  alerts.
- **Ship a `threat_model.md` with the code.** Keep it in the repo and update
  it as the code changes. The scanner reads it before searching, which lets
  it skip known non-issues like a buffer overread on a user-controlled file
  or a bad value from a trusted config.

## Where it plugs in: pre-scan scope and post-scan filter

Use the threat model in two places. **Pre-scan, as scope:** partition the
code, prioritize targets, skip what's out of scope. This is how you make
large codebases tractable when you can't scan everything. **Post-scan, as
filter:** scan broadly, then use the threat model to triage what came back.
This gives higher coverage at the cost of more triage work. Most teams end
up doing both.

See [triage.md](triage.md) for how the threat model feeds severity scoring,
and [best-practices.md](best-practices.md) #1-2 and #18 for related
principles.
