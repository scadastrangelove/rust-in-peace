/**
 * Shared helpers for the rip CodeQL/Rust candidate generators.
 *
 * These queries are the CodeQL half of an A/B against `rules/astgrep/rules/cls-*.yml`.
 * They are CANDIDATE GENERATORS, never verdicts: a reachability judge and a finder run
 * downstream, so a false positive costs one agent read and a false negative is permanent.
 * Tune for recall.
 *
 * ---------------------------------------------------------------------------
 * SCOPE NOTE — why every query filters on `isCrateLocal`
 *
 * A `--build-mode=none` Rust database contains far more than the crate under analysis:
 * std/core/alloc and every dependency are extracted as *library* source
 * (`extract_dependencies_as_source: false`, but the sysroot is still parsed). Measured on
 * the lopdf database: 2068 `.rs` files and 59,566 `Function`s in the database against 101
 * files and ~1,100 functions in lopdf itself. Without this filter every query below
 * reports std's internals.
 */

import rust

/**
 * Holds if `f` belongs to the crate under analysis rather than to std or a dependency.
 *
 * Stated as an EXCLUSION of the toolchain roots rather than an inclusion of one corpus
 * path, so the queries run unchanged against any checkout. Measured on the fixture
 * database: 1964 of 1968 extracted `.rs` files live under `.rustup/toolchains`, 3 under
 * the CodeQL distribution, and 1 is the crate.
 */
predicate isCrateLocalFile(File f) {
  f.getExtension() = "rs" and
  not f.getAbsolutePath().matches("%/.rustup/%") and
  not f.getAbsolutePath().matches("%/.cargo/%") and
  not f.getAbsolutePath().matches("%/codeql-home/%") and
  not f.getAbsolutePath().matches("%/codeql/qlpacks/%") and
  not f.getAbsolutePath().matches("%/registry/src/%") and
  not f.getAbsolutePath().matches("%/rustlib/%")
}

/** Holds if `n` is source of the crate under analysis. */
predicate isCrateLocal(AstNode n) { isCrateLocalFile(n.getFile()) }

/**
 * Holds if some identifier inside `root` matches `re`.
 *
 * NOT `root.toString().regexpMatch(re)`. CodeQL abbreviates `toString()` for
 * composite nodes — a `BinaryExpr` prints as `"... >= ..."`, with every operand
 * name erased. A first draft of `RecursionCycle.ql` used the `toString` form and
 * consequently reported all five lopdf recursions that PR #531/#533 had already
 * fixed with an explicit `depth >= MAX_NESTING_DEPTH` bound. The same trap costs a
 * `Meta.toString()` test its `#[cfg(test)]` detection and a `TypeRepr.toString()`
 * test its `&[u8]` detection — this predicate walks the subtree instead, and every
 * name-shaped test in these queries goes through it.
 */
bindingset[re]
predicate mentionsIdent(AstNode root, string re) {
  exists(NameRef nr |
    (nr = root or nr.getParentNode+() = root) and
    nr.getText().regexpMatch(re)
  )
  or
  exists(Name n | (n = root or n.getParentNode+() = root) and n.getText().regexpMatch(re))
}

/**
 * Holds if `n` sits in test / bench / example / fuzz code.
 *
 * The ast-grep rules exclude these paths for the same reason (they are not attack surface
 * and they dominate raw volume); keeping the exclusion identical is what makes the A/B
 * comparable. Note this is a PATH test only — `#[cfg(test)] mod tests` inside `src/` is a
 * separate matter, and is handled by `inCfgTestModule`.
 */
predicate inNonProductionPath(AstNode n) {
  exists(string p | p = n.getFile().getRelativePath() |
    p.matches("tests/%") or
    p.matches("%/tests/%") or
    p.matches("benches/%") or
    p.matches("%/benches/%") or
    p.matches("examples/%") or
    p.matches("%/examples/%") or
    p.matches("fuzz/%") or
    p.matches("%/fuzz/%") or
    p.matches("%-afl/%") or
    p.matches("%_test/%")
  )
}

/**
 * Holds if `n` is inside a `#[cfg(test)]` or `#[test]` item.
 *
 * Reached through the attribute's PARENT rather than an `Item.getAnAttr()` accessor,
 * which the generated API does not expose on the `Item` supertype. The `test` token is
 * matched STRUCTURALLY: `Meta.toString()` abbreviates like every other composite node,
 * and a first draft testing that string let all six of quick-xml `src/name.rs`'s
 * `#[cfg(test)] mod test` pops through as candidates.
 */
predicate inCfgTestModule(AstNode n) {
  exists(Attr a, AstNode owner |
    mentionsIdent(a, "^test$") and
    owner = a.getParentNode() and
    (n = owner or n.getParentNode+() = owner)
  )
}

/** Holds if `n` is production source of the crate under analysis. */
predicate isProductionCrateCode(AstNode n) {
  isCrateLocal(n) and
  not inNonProductionPath(n) and
  not inCfgTestModule(n)
}

/**
 * Gets the nearest enclosing named `Function` of `n`, stepping out through closures.
 *
 * `AstNode.getEnclosingCallable()` returns a `Callable`, which is a `Function` OR a
 * `ClosureExpr`. Recursion laundered through a closure (`cls-recursion` limit L3) only
 * becomes visible if closures are transparent here, so they are.
 */
Function getEnclosingFunction(AstNode n) {
  exists(Callable c | c = n.getEnclosingCallable() |
    result = c
    or
    c instanceof ClosureExpr and result = getEnclosingFunction(c)
  )
}

/** Gets the `impl` or `trait` block containing `f`, if any. */
AstNode getOwningItem(Function f) {
  result = f.getParentNode+() and
  (result instanceof Impl or result instanceof Trait) and
  // nearest such ancestor
  not exists(AstNode mid |
    mid = f.getParentNode+() and
    (mid instanceof Impl or mid instanceof Trait) and
    mid.getParentNode+() = result
  )
}

/** Gets a readable `Type::method` label for `f`. */
string qualifiedName(Function f) {
  exists(Impl i | i = getOwningItem(f) |
    result = i.getSelfTy().toString() + "::" + f.getName().getText()
  )
  or
  exists(Trait t | t = getOwningItem(f) |
    result = "trait " + t.getName().getText() + "::" + f.getName().getText()
  )
  or
  not exists(getOwningItem(f)) and result = f.getName().getText()
}

/** The depth-ish vocabulary, shared with `cls-recursion.yml`'s G1 suppressor. */
string depthWordRegex() {
  result = "(?i).*(depth|recurs|nest|level|budget|fuel|remain|quota|limit).*"
}
