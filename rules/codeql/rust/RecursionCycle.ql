/**
 * @name Unbounded recursion cycle (call-graph)
 * @description A cycle in the resolved call graph with no depth bound on any member.
 *              Ports `rules/astgrep/rules/cls-recursion.yml` onto a real call graph.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id rip/rust/recursion-cycle
 * @tags security
 *       candidate-generator
 *       external/cwe/cwe-674
 */

/*
 * =============================================================================
 * WHAT CODEQL BOUGHT OVER cls-recursion.yml
 * =============================================================================
 *
 * cls-recursion.yml documents nine limits. This query closes four of them, and
 * only because it has a resolved call graph (`Call.getARuntimeTarget()`), which
 * is a type-inference result, not a syntactic one:
 *
 *   L1  MUTUAL RECURSION a()->b()->a(). The ast-grep rule's own header calls it
 *       "the single biggest blind spot ... not detected at all". Here it is just
 *       `callEdge+(f, f)` with a cycle of length >= 2.
 *   L2  `self.left.insert(v)` — recursion through a same-typed FIELD. The rule
 *       excludes the field-receiver form entirely because it is "indistinguishable
 *       from `self.reader.config()` without type information". PARTIALLY closed,
 *       and the boundary was measured, not assumed:
 *         FIRES   `let l: &mut Tree = self.left.as_mut().unwrap(); l.insert(v)`
 *         MISSES  `if let Some(l) = &mut self.left { l.insert(v) }`
 *         MISSES  `self.left.as_ref().unwrap().depth()`
 *       i.e. the receiver's type has to survive inference through the
 *       `Option<Box<T>>` wrapper, and under `--build-mode=none` it often does not.
 *       Where inference gives up the call is `<<UNRESOLVED>>` and the edge is simply
 *       absent — a silent miss, not a noisy one.
 *   L3  Recursion through a trait object / generic callback. `getARuntimeTarget()`
 *       expands a trait-method call to every impl of that method, so `dyn Handler`
 *       dispatch produces edges (verified on the fixture: `H::handle` calling
 *       through `&dyn Handler` is reported).
 *   L8  `crate::module::f()` self-calling. The syntactic rule restricts the
 *       qualifier to `Self`/`self` to avoid the rustls `fn fips() { fips() }`
 *       delegation FP; path resolution removes the need for the restriction. Follows
 *       from the same `getStaticTarget()` machinery but was not separately measured.
 *
 * WHAT CODEQL DID NOT BUY (measured, not assumed):
 *
 *   L5  Guard ORDER (a depth test placed after the recursive call) — this query
 *       does not consult the CFG for the depth bound either. See CfgPop.ql for the
 *       dominance machinery; it was deliberately not wired in here because a depth
 *       counter is usually threaded through a PARAMETER across the whole cycle, so
 *       per-function dominance answers the wrong question.
 *   L6/L9 The depth-bound recogniser below is still name-shaped, exactly as in the
 *       syntactic rule. CodeQL does not help here: "is this integer a depth?" is not
 *       a type question.
 *   L7  Structural boundedness (fixed-arity ASTs, tail recursion on a shrinking
 *       slice) is invisible to both tools.
 *
 * AND THE TWO THINGS CODEQL LOST:
 *
 *   SERDE RE-ENTRANCY, which is where BOTH open upstream findings live. The
 *   recursion in quick-xml #982 and msgpack-rust #382 goes through a
 *   CALLER-CHOSEN generic (`seed.deserialize(self)`, `visitor.visit_map(..)`).
 *   Monomorphisation is not known, so the call has no target: probing
 *   quick-xml `src/de/map.rs:1134` returns `<<UNRESOLVED>>` for
 *   `.deserialize_seq(..)`. The cycle breaks exactly at the re-entrancy point and
 *   this query reports NONE of the six ground-truth call sites, which
 *   `cls-recursion.yml`'s name-defined serde rule catches 6/6.
 *
 *   `#[cfg(...)]`-gated code. The extractor evaluates ONE cfg configuration;
 *   ast-grep is textual and sees every arm. Measured on lopdf `src/reader.rs`:
 *   72 `fn` in the file, 53 extracted — the 19 missing are exactly the
 *   `#[cfg(feature = "async")]` duplicates, which lopdf's optional `tokio`
 *   dependency could not be resolved for offline. Any recursion that only exists
 *   under an unresolvable feature is a permanent, silent CodeQL miss.
 */

import rust
import RipRust

/**
 * Holds if a call inside `caller` resolves to `callee`.
 *
 * `getARuntimeTarget()` rather than `getStaticTarget()` on purpose: the static
 * target of a trait-method call is the trait's declaration, which has no body and
 * therefore no outgoing edges, so the cycle would break exactly at the trait
 * object — which is limit L3, the thing this query exists to close. The runtime
 * variant expands to every impl, which over-approximates. That is the correct
 * direction of error for a candidate generator.
 */
predicate callEdge(Function caller, Function callee, Call c) {
  isProductionCrateCode(c) and
  caller = getEnclosingFunction(c) and
  callee = c.getARuntimeTarget() and
  isCrateLocal(callee)
}

/** Holds if `c`'s edge to `callee` is a DEFINITE call, not a trait-impl expansion. */
predicate staticEdge(Function callee, Call c) { callee = c.getStaticTarget() }

/**
 * Holds if `f`'s apparent self-recursion is an artefact of `getARuntimeTarget()`
 * expanding a DELEGATION to a differently-typed inner value.
 *
 * `fn read(&mut self, b: &mut [u8]) { self.0.read(b) }` in a newtype wrapper is not
 * recursion: the inner `self.0` is a different type. But `getARuntimeTarget()` expands
 * `Read::read` to every impl of it, including this one, and manufactures a self-loop.
 * Measured, this single pattern was the dominant false positive of the class —
 * 24 of 33 sites in msgpack-rust (`rmp-serde/src/config.rs` config delegation),
 * 3 of 5 in quick-xml (`BinaryStream`), 3 of 3 in image-png (`RandomChunkWriter`).
 *
 * The discrimination is exactly the one `cls-recursion.yml` limit L2 says is
 * impossible without types: a field receiver whose static target IS this function is
 * genuine subtree recursion (a BST `self.left.insert(v)`), and one whose static
 * target is anything else is delegation. Only the latter is suppressed, so L2's real
 * case survives.
 */
predicate isDelegationArtefact(Function f) {
  exists(Call c | callEdge(f, f, c)) and
  forall(Call c | callEdge(f, f, c) |
    not staticEdge(f, c) and
    c.(MethodCall).getReceiver() instanceof FieldExpr
  )
}

/** The binary projection of `callEdge`, so `+` can be applied to it. */
predicate calls(Function caller, Function callee) { callEdge(caller, callee, _) }

/** Holds if `f` participates in a call-graph cycle. */
predicate inCycle(Function f) { calls+(f, f) }

/**
 * Holds if `f` shows a depth-bound shape: some condition mentions a depth-ish
 * quantity, AND a counter or container advances.
 *
 * Deliberately identical in spirit to cls-recursion's G1 suppressor, including its
 * weaknesses, so that the A/B measures the call graph and not two different
 * definitions of "bounded". Merely THREADING `depth + 1` without ever comparing it
 * is not enough; the test alone is not enough either.
 */
predicate hasDepthBound(Function f) {
  // NB `getEnclosingFunction`, not `getEnclosingCallable`. lopdf's parser combinators are
  // `fn nested_literal_string(depth: usize) -> impl Fn(..)`: both the `if depth == 0` bail
  // and the `depth - 1` advance live inside the RETURNED CLOSURE, so a `getEnclosingCallable`
  // test binds the closure and the function looks unbounded. Measured: that draft reported
  // lopdf `src/parser/mod.rs:190/208/281/293/299/389/390/401`, all of them correctly bounded.
  exists(Expr cond |
    (
      cond = any(IfExpr e | getEnclosingFunction(e) = f).getCondition() or
      cond = any(WhileExpr e | getEnclosingFunction(e) = f).getCondition() or
      cond = any(MatchGuard g | getEnclosingFunction(g) = f).getCondition()
    ) and
    mentionsIdent(cond, depthWordRegex())
  ) and
  exists(BinaryExpr adv |
    getEnclosingFunction(adv) = f and
    adv.getOperatorName() = ["+", "-", "+=", "-="] and
    mentionsIdent(adv, depthWordRegex())
  )
  or
  // A visited-set cycle breaker is a bound too, and is how lopdf PR #531/#533 fixed
  // `collect_resources`: `if already_seen.contains(&id) { return Err(..) }`.
  exists(IfExpr e, MethodCallExpr m |
    getEnclosingFunction(e) = f and
    m.getParentNode*() = e.getCondition() and
    m.getIdentifier().getText() = ["contains", "contains_key", "insert"] and
    exists(Expr ret |
      ret.getParentNode*() = e.getThen() and
      (ret instanceof ReturnExpr or ret instanceof BreakExpr)
    )
  )
  or
  // a depth-ish macro guard (`depth_count!` in rmp-serde) — the extractor leaves the
  // token tree opaque, so match the macro NAME, which is all either tool can see.
  exists(MacroCall mc |
    getEnclosingFunction(mc) = f and
    mc.getPath().toString().regexpMatch("(?i).*(depth|recurs|nest|level|budget|fuel).*")
  )
}

/** Holds if the whole cycle through `f` is bounded somewhere. */
predicate cycleIsBounded(Function f) {
  exists(Function g | (g = f or calls+(f, g) and calls+(g, f)) | hasDepthBound(g))
}

/** Gets the number of distinct functions in `f`'s strongly connected component. */
int cycleSize(Function f) {
  result = count(Function g | g = f or (calls+(f, g) and calls+(g, f)))
}

/** Gets the provenance of the edge `c` -> `callee`, for triage. */
string edgeKind(Function callee, Call c) {
  staticEdge(callee, c) and result = " [static edge]"
  or
  not staticEdge(callee, c) and result = " [runtime-expanded edge]"
}

/** Classifies the recursion shape, for triage. */
string shape(Function f) {
  cycleSize(f) >= 2 and result = "MUTUAL"
  or
  cycleSize(f) = 1 and
  exists(Call c | callEdge(f, f, c) and c instanceof MethodCall) and
  result = "SELF-method"
  or
  cycleSize(f) = 1 and
  not exists(Call c | callEdge(f, f, c) and c instanceof MethodCall) and
  result = "SELF-path"
}

from Function f, Call c, Function callee
where
  inCycle(f) and
  callEdge(f, callee, c) and
  (callee = f or (calls+(callee, f) and inCycle(callee))) and
  not cycleIsBounded(f) and
  not isDelegationArtefact(f)
select c,
  shape(f) + " recursion with no depth bound" + edgeKind(callee, c) + ": " + qualifiedName(f) + " -> " +
    qualifiedName(callee) + " (cycle size " + cycleSize(f) + ") @ " +
    c.getFile().getRelativePath() + ":" + c.getLocation().getStartLine()
