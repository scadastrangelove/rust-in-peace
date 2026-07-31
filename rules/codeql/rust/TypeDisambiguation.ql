/**
 * @name Type-disambiguation probes (call target and integer width)
 * @description Two things the syntactic rules provably cannot do: tell `slice::join` from
 *              `Path::join`, and tell a `u16` counter from an `i32` one.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id rip/rust/type-disambiguation
 * @tags security
 *       candidate-generator
 *       external/cwe/cwe-190
 */

/*
 * =============================================================================
 * WHAT CODEQL BOUGHT — this is the cheap, decisive one
 * =============================================================================
 *
 * The ast-grep rules key on method NAMES. Two measured consequences:
 *
 *  (A) `object` `crates/rewrite/src/elf.rs:351` — `runpaths.join(&[b':'][..])`.
 *      A name-keyed rule that treats `join` as path construction reports this. It is
 *      `[Vec<u8>]::join`, a slice concatenation, and the finding is a false positive.
 *      Nothing textual distinguishes it from `Path::join`; `getStaticTarget()` does,
 *      because it resolves through the receiver's inferred type.
 *
 *  (B) quick-xml `NamespaceResolver`'s `nesting_level: u16` overflowed at 65,536
 *      while its `i32`/`usize` siblings in the same file never could. cls-alloc's
 *      header lists this as a permanent blind spot: "A cap enforced by a TYPE.
 *      `hdr.count: u8` can never exceed 255; the matcher sees an identifier."
 *      `inferType` reads the width off the declaration.
 *
 * Both directions matter and they are not symmetric:
 *   - (A) is FP REMOVAL. Cheap, and safe under the pipeline's cost model.
 *   - (B) is FP removal AND recall: it lets a rule fire only on the narrow-typed
 *     counters, which is a ~2-orders-of-magnitude reduction in candidate volume for
 *     the counter-overflow family without dropping the shape that actually overflows.
 *
 * WHAT IT DID NOT BUY: nothing here needs a caveat about macros or cfg beyond the
 * global ones in RipRust.qll — type inference is the part of the Rust extractor that
 * works best under `--build-mode=none`, because the sysroot is extracted as a library
 * even when nothing is compiled.
 */

import rust
private import codeql.rust.internal.typeinference.TypeInference as TI
import RipRust

/**
 * Method names that are ambiguous across std types, where a name-keyed rule must
 * guess. `join` is the ground-truth case; the rest are the same hazard.
 */
string ambiguousMethodName() {
  result =
    [
      "join", // slice::join (concat) vs Path::join (path build) vs JoinHandle::join
      "read", // io::Read::read vs a domain reader
      "get", // map lookup vs slice::get vs domain accessor
      "insert", // Vec::insert(idx, v) vs HashMap::insert(k, v) vs Option::insert
      "extend", // Extend::extend vs a domain extend
      "split", // str::split vs slice::split vs domain split
      "len", "take", "next", "write", "push", "with_capacity", "resize", "reserve",
      "from_str_radix", "parse"
    ]
}

/**
 * Gets a label for where `f` is defined.
 *
 * Uses the ABSOLUTE path: the resolved target of `paths.join(..)` lives in
 * `.rustup/.../alloc/src/slice.rs`, which is outside the analysed source root, so
 * `File.getRelativePath()` has no result there. A first draft used the relative form
 * and consequently produced zero rows for the one probe the query exists to run.
 */
string definitionSite(Function f) {
  result = f.getName().getText() + " @ " + f.getFile().getAbsolutePath() + ":" +
      f.getLocation().getStartLine() +
      concat(Impl i | i = getOwningItem(f) | " [impl " + i.getSelfTy().toString() + "]", ",")
}

/** Holds if `t` is a narrow integer type — one that overflows at a reachable count. */
predicate isNarrowInt(TI::Type t, string name) {
  name = t.toString() and
  name = ["u8", "u16", "i8", "i16"]
}

/** Gets the value at which `tname` wraps, as text. */
string wrapPoint(string tname) {
  tname = "u8" and result = "256"
  or
  tname = "u16" and result = "65536"
  or
  tname = "i8" and result = "+/-128"
  or
  tname = "i16" and result = "+/-32768"
}

/** Holds if `e` is an unchecked increment of a place. */
predicate uncheckedIncrement(AstNode e, Expr place) {
  exists(BinaryExpr b |
    b = e and
    b.getOperatorName() = ["+=", "-=", "*="] and
    place = b.getLhs()
  )
  or
  exists(BinaryExpr assign, BinaryExpr arith |
    assign = e and
    assign.getOperatorName() = "=" and
    place = assign.getLhs() and
    arith = assign.getRhs() and
    arith.getOperatorName() = ["+", "*"]
  )
}

/** Holds if `place` is protected by a checked/saturating/wrapping form somewhere. */
predicate hasCheckedArithmetic(Function f) {
  exists(MethodCallExpr m |
    getEnclosingFunction(m) = f and
    m.getIdentifier().getText().regexpMatch("(checked|saturating|wrapping|overflowing)_.*")
  )
}

/*
 * ---------------------------------------------------------------------------
 * PROBE A — resolved call target for an ambiguously-named method.
 * ---------------------------------------------------------------------------
 */

predicate probeA(AstNode at, string msg) {
  exists(MethodCallExpr m, Function target |
    at = m and
    isProductionCrateCode(m) and
    m.getIdentifier().getText() = ambiguousMethodName() and
    target = m.getStaticTarget() and
    msg =
      "TYPE-RESOLVED CALL: `." + m.getIdentifier().getText() + "()` resolves to " +
        definitionSite(target) + " [receiver type: " +
        concat(TI::inferType(m.getReceiver()).toString(), ",") + "]"
  )
}

/*
 * ---------------------------------------------------------------------------
 * PROBE B — a counter whose declared width is narrow enough to wrap.
 * ---------------------------------------------------------------------------
 */

predicate probeB(AstNode at, string msg) {
  exists(Expr place, string tname |
    isProductionCrateCode(at) and
    uncheckedIncrement(at, place) and
    isNarrowInt(TI::inferType(place), tname) and
    not hasCheckedArithmetic(getEnclosingFunction(at)) and
    msg =
      "NARROW COUNTER: increment of a `" + tname + "` place in " +
        qualifiedName(getEnclosingFunction(at)) + " — wraps at " + wrapPoint(tname) +
        ", and no checked/saturating form appears in this function"
  )
}

from AstNode at, string msg
where
  (probeA(at, msg) or probeB(at, msg)) and
  isProductionCrateCode(at)
select at, msg + " @ " + at.getFile().getRelativePath() + ":" + at.getLocation().getStartLine()
