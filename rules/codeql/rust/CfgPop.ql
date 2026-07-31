/**
 * @name Pop with no dominating emptiness/length guard
 * @description A stack/queue pop that is not dominated by a sufficient guard on the same
 *              collection. Ports `rules/astgrep/rules/cls-pop.yml` onto a real CFG.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id rip/rust/pop-no-dominating-guard
 * @tags security
 *       candidate-generator
 *       external/cwe/cwe-1284
 */

/*
 * =============================================================================
 * WHAT CODEQL BOUGHT OVER cls-pop.yml
 * =============================================================================
 *
 * cls-pop.yml's header is unusually explicit about what it is not:
 *
 *     "THIS IS NOT DOMINANCE. It is textual precedence over the ancestor chain.
 *      It over-suppresses whenever a textually-earlier guard does not actually
 *      dominate ... No control-flow graph is consulted, and none is claimed."
 *
 * This query consults one. Three things follow, and they are the entire reason it
 * exists:
 *
 *  (1) REAL DOMINANCE, not textual precedence. A guard suppresses a pop only when
 *      a specific OUTCOME EDGE of the guard's condition dominates the pop's basic
 *      block (`ConditionBasicBlock.edgeDominates`). A guard in a sibling `if` arm,
 *      or one whose body does not bail out, therefore does NOT suppress — those
 *      are two of the syntactic rule's listed over-suppressions.
 *
 *  (2) COMPOUND CONDITIONS COME FREE — MATCH ARMS DO NOT. cls-pop lists
 *      `if a && s.len() < 4`, `if s.len() == 4 || (..)`, and
 *      `match s.len() { 1 => s.pop().unwrap(), .. }` as things it "CANNOT see".
 *      CodeQL's CFG short-circuits `&&`/`||` into separate condition blocks, so the
 *      first two are handled by the same `edgeDominates` call with no extra code
 *      (verified: `if s.len() == 4 || (w && s.len() == 5)` produces four distinct
 *      `ConditionBasicBlock`s, and ttf-parser `cff1.rs:539..547` — six ast-grep hits
 *      under exactly that guard — all go silent).
 *      MATCH DISPATCH DOES NOT. Measured on the fixture: for
 *      `match s.len() { 1 => s.pop().unwrap(), _ => 0.0 }` there is NO
 *      `ConditionBasicBlock` anywhere in the expression, so there is no edge to
 *      dominate with. An attempted fix relating the arm pattern back to the
 *      scrutinee changed nothing and was removed. On match-arm guards the two tools
 *      TIE, and both report the pop.
 *
 *  (3) THE RULE CAN NOW COUNT PAST ONE. cls-pop: "ast-grep cannot count pops, so a
 *      guard that proves N and a block that pops N+1 is the permanent hazard". Its
 *      compromise re-fires every pop after the first and pays 14 false positives in
 *      ttf-parser `charstring.rs` for it. Here `popRank` counts how many
 *      same-collection pops DOMINATE this one, and a guard proving N suppresses
 *      only ranks 1..N. Arity-correct code goes quiet; the (N+1)-th pop still fires.
 *
 * WHAT CODEQL DID NOT BUY:
 *
 *   - `assert!(!s.is_empty())` as a guard is still invisible, and for the same
 *     reason in both tools: the macro is not expanded. Measured on this box,
 *     `assert!` expansion rate under `--build-mode=none` is 0/321 in lopdf and
 *     0/83 in image-png. CodeQL sees a `MacroCall` with an opaque `TokenTree` and
 *     nothing inside it. TIED, not won.
 *   - Interprocedural guards (`fn helper(s) { if s.is_empty() { return } s.pop() }`
 *     called only from a validating caller) are still missed. Dominance is
 *     intraprocedural here by construction.
 *   - Open-coded pops (`self.len -= 1; self.data[self.len]`) are out of class for
 *     both tools.
 */

import rust
import codeql.rust.controlflow.ControlFlowGraph
import codeql.rust.controlflow.BasicBlocks
import RipRust

/**
 * A pop-shaped call.
 *
 * Method-name keyed and NOT gated on `unwrap`, on the receiver's name, or on the
 * return type — deliberately identical to cls-pop, whose v1 required
 * `.pop().unwrap()` and consequently scored zero on the crate it came from.
 * ttf-parser's `ArgumentsStack::pop() -> f32` is infallible by signature and
 * underflows silently; that is the shape that matters.
 */
class PopCall extends MethodCallExpr {
  PopCall() {
    this.getIdentifier().getText() =
      ["pop", "pop_front", "pop_back", "pop_first", "pop_last"]
  }

  Expr getCollection() { result = this.getReceiver() }
}

/**
 * Holds if `a` and `b` denote the same collection.
 *
 * Structural, not textual: same local variable, or the same field read off the same
 * base. This is where type information starts to matter — `p.stack` and `p.stack`
 * in two different functions are different collections, and CodeQL knows it because
 * `Variable` is scoped.
 */
predicate sameCollection(Expr a, Expr b) {
  exists(Variable v |
    v = a.(VariableAccess).getVariable() and v = b.(VariableAccess).getVariable()
  )
  or
  exists(FieldExpr fa, FieldExpr fb |
    fa = a and
    fb = b and
    fa.getIdentifier().getText() = fb.getIdentifier().getText() and
    sameCollection(fa.getContainer(), fb.getContainer())
  )
  or
  // `self.stack` reached via an auto-deref/paren wrapper
  exists(ParenExpr p | p = a and sameCollection(p.getExpr(), b))
  or
  exists(ParenExpr p | p = b and sameCollection(a, p.getExpr()))
}

/**
 * Holds if `cond` tests the size of `coll`.
 *
 * Kept NARROW on purpose. cls-pop's contract is "unrecognised guard spelling must
 * mean candidate, never clean", so widening this predicate costs recall directly.
 * The dominance test below is what got stronger, not the guard vocabulary.
 */
predicate sizeGuard(Expr cond, Expr coll) {
  exists(MethodCallExpr m |
    m = cond.getParentNode*().(Expr) or m.getParentNode*() = cond
  |
    m.getIdentifier().getText() = ["len", "is_empty", "count"] and
    sameCollection(m.getReceiver(), coll)
  )
  or
  // custom emptiness spellings: `self.len == 0`, `self.top > 0`, `self.n < 2`
  exists(BinaryExpr b, FieldExpr fe |
    (b = cond or b.getParentNode*() = cond) and
    fe.getParentNode*() = b and
    fe.getIdentifier().getText() = ["len", "top", "size", "count", "n", "depth"] and
    sameCollection(fe.getContainer(), coll)
  )
}

/** Gets the CFG node of `n`, in the CFG scope in which it appears. */
CfgNode cfg(AstNode n) { result = n.getACfgNode() }

/** Gets a basic block containing a CFG node of `n`. */
BasicBlock bbOf(AstNode n) { result.getANode() = cfg(n) }

/**
 * Holds if some CFG node of `a` dominates some CFG node of `b`.
 *
 * Written out rather than using `ControlFlowNode.dominates` because the Rust CFG
 * exposes `Node` without the shared library's node-level dominance wrapper. Basic
 * block dominance plus within-block index is the same relation.
 */
predicate cfgDominates(AstNode a, AstNode b) {
  exists(BasicBlock ba, BasicBlock bbb |
    ba = bbOf(a) and bbb = bbOf(b)
  |
    ba.strictlyDominates(bbb)
    or
    ba = bbb and
    exists(int i, int j | ba.getNode(i) = cfg(a) and bbb.getNode(j) = cfg(b) and i <= j)
  )
}

/**
 * Holds if some outcome edge of `cond` dominates `target`.
 *
 * This is the whole point of the query. `ConditionBasicBlock.edgeDominates(bb, s)`
 * holds when every path to `bb` leaves the condition by successor `s` — i.e. the
 * guard was not merely written earlier in the file, it was *taken*.
 */
predicate guardEdgeDominates(Expr cond, AstNode target) {
  exists(ConditionBasicBlock cbb, BasicBlock tbb |
    cbb.getLastNode().getAstNode() = cond and
    tbb = bbOf(target) and
    cbb.edgeDominates(tbb, _)
  )
}

/**
 * Gets the number of elements a guard on `coll` proves are present, when that number
 * is a literal.
 *
 * `if s.len() < 4 { return }` proves 4; `is_empty` / `!is_empty` prove 1. A guard
 * against a non-literal (`if s.len() < len { return }`) yields no result and is
 * handled as "proves at least 1" by `provenAtLeast`.
 */
int provenLiteral(Expr cond, Expr coll) {
  sizeGuard(cond, coll) and
  exists(BinaryExpr b, IntegerLiteralExpr lit |
    (b = cond or b.getParentNode*() = cond) and
    lit.getParentNode*() = b and
    result = lit.getTextValue().toInt() and
    result > 0
  )
}

/** Gets the number of elements a dominating guard on `coll` proves, defaulting to 1. */
int provenAtLeast(Expr cond, Expr coll) {
  result = max(provenLiteral(cond, coll))
  or
  sizeGuard(cond, coll) and not exists(provenLiteral(cond, coll)) and result = 1
}

/**
 * Gets the 1-based rank of `p` among the same-collection pops that dominate it AND
 * are themselves dominated by `cond`.
 *
 * The rank is measured RELATIVE TO THE GUARD, not from the top of the function.
 * That matters: ttf-parser `charstring.rs` re-establishes the invariant mid-block
 * with `if self.stack.len() == 1 { self.stack.pop() }` after four earlier pops. A
 * function-wide rank would call that pop the fifth and fire; guard-relative it is
 * the first after its own guard, which is what the code actually proves.
 *
 * This is the count cls-pop explicitly could not do ("ast-grep cannot count pops").
 */
int popRankAfter(Expr cond, PopCall p) {
  result =
    count(PopCall q |
      sameCollection(q.getCollection(), p.getCollection()) and
      getEnclosingFunction(q) = getEnclosingFunction(p) and
      cfgDominates(q, p) and
      cfgDominates(cond, q)
    )
}

/** Gets the rank of `p` among ALL same-collection pops dominating it, for reporting. */
int popRank(PopCall p) {
  result =
    count(PopCall q |
      sameCollection(q.getCollection(), p.getCollection()) and
      getEnclosingFunction(q) = getEnclosingFunction(p) and
      cfgDominates(q, p)
    )
}

/**
 * Holds if the `Option` returned by `p` is destructured or defaulted.
 *
 * Carried over unchanged from cls-pop's one SOUND suppression: these names exist on
 * `Option`, so their presence proves both that the pop is the fallible std kind and
 * that the `None` case is handled. `unwrap`/`expect` are deliberately absent — they
 * prove `Option`-ness and then throw the proof away.
 */
predicate optionHandled(PopCall p) {
  exists(MethodCallExpr m |
    m.getReceiver() = p and
    m.getIdentifier().getText() =
      [
        "unwrap_or", "unwrap_or_else", "unwrap_or_default", "ok_or", "ok_or_else",
        "map_or", "map_or_else", "and_then", "is_some", "is_none", "filter", "take_if"
      ]
  )
  or
  exists(TryExpr t | t.getExpr() = p)
  or
  // `if let Some(x) = s.pop()`, including the binding form `if let k @ Some(_) = s.pop()`.
  // Matched structurally: `Pat.toString()` abbreviates (`kids @ Some(_)` prints without
  // "Some"), and a first draft that tested the string reported lopdf `document.rs:917`,
  // which is Option-handled and which the syntactic rule correctly stays silent on.
  exists(LetExpr l |
    l.getScrutinee() = p and mentionsIdent(l.getPat(), "^(Some|None|Ok|Err)$")
  )
  or
  exists(MatchExpr m | m.getScrutinee() = p)
  or
  exists(LetStmt l | l.getInitializer() = p and exists(l.getLetElse()))
}

/** Holds if `p` is suppressed by a dominating, arity-sufficient guard. */
predicate hasSufficientDominatingGuard(PopCall p) {
  exists(Expr cond |
    sizeGuard(cond, p.getCollection()) and
    guardEdgeDominates(cond, p) and
    provenAtLeast(cond, p.getCollection()) >= popRankAfter(cond, p)
  )
}

from PopCall p
where
  isProductionCrateCode(p) and
  not optionHandled(p) and
  not hasSufficientDominatingGuard(p)
select p,
  "pop with no dominating guard sufficient for rank " + popRank(p) + " on this collection, in " +
    qualifiedName(getEnclosingFunction(p)) + " @ " + p.getFile().getRelativePath() + ":" +
    p.getLocation().getStartLine()
