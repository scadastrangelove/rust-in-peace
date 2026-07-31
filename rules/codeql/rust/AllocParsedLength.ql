/**
 * @name Allocation sized by a parsed length (interprocedural)
 * @description An allocation or reservation whose size flows, across function boundaries,
 *              from bytes the crate parses. Ports `rules/astgrep/rules/cls-alloc.yml`
 *              onto real taint tracking.
 * @kind path-problem
 * @problem.severity warning
 * @precision low
 * @id rip/rust/alloc-sized-by-parsed-length
 * @tags security
 *       candidate-generator
 *       external/cwe/cwe-770
 *       external/cwe/cwe-789
 */

/*
 * =============================================================================
 * WHAT CODEQL BOUGHT — AND THE TWO REASONS THE BUILT-IN QUERY RETURNED ZERO
 * =============================================================================
 *
 * cls-alloc.yml's central admission: "ast-grep has NO DATAFLOW. source->sink cannot
 * be traced." Its author measured that the source-connected shape occurs once in
 * twelve crates, because real parsers thread lengths through struct fields and helper
 * returns. That is exactly what `TaintTracking::Global` is for, and it is the one
 * thing here CodeQL genuinely adds.
 *
 * But the built-in `rust/uncontrolled-allocation-size` returns 0 on lopdf, image-png
 * and miniz_oxide, and BOTH reasons are structural, not tuning:
 *
 *  (1) NO THREAT-MODEL SOURCE EXISTS IN A LIBRARY CRATE. The built-in's source is
 *      `ActiveThreatModelSource` — env vars, CLI args, file/network reads. A codec
 *      crate reads none of those: its untrusted bytes arrive as a `&[u8]` PARAMETER
 *      of its own public API. This query therefore models the parser boundary
 *      instead (`ByteInputParameter` below). That single change is what makes
 *      dataflow applicable to this corpus at all.
 *
 *  (2) THE `vec!` SINK IS INVISIBLE. Measured on this box under `--build-mode=none`:
 *      `vec!` macro-expansion rate is 0/285 in lopdf, 0/93 in image-png, 0/15 in
 *      miniz_oxide. A direct AST probe of lopdf `src/parser_aux.rs:577`, the exact
 *      site PR #533 fixed, returns three nodes and no more:
 *          577  MacroCall "vec!..."   TokenTree   MacroExpr
 *      There is no `IndexExpr field_widths[0]`, no `CastExpr`, no `VariableAccess`.
 *      The size expression does not exist in the database, so no dataflow of any
 *      configuration can reach it. ast-grep at least has the raw token TEXT and can
 *      regex it — which is precisely how cls-alloc catches the pre-fix lopdf site.
 *
 *      On this sub-class CodeQL LOSES to the syntactic rule, and it loses on the
 *      ground truth. `MacroOpaqueAllocation.ql` is the honest mitigation: it reports
 *      the `vec!` call itself when the enclosing function parses bytes, so the class
 *      is noisy rather than silent.
 *
 *  (3) IMPLICIT-SIZE DECOMPRESSION IS NOT A DATAFLOW QUESTION AT ALL. png's
 *      `fdeflate::decompress_to_vec(v)` (`src/text_metadata.rs:309/482/570`) has no
 *      length field anywhere. Requiring a connected source finds it 0 times here; it
 *      is reported on shape by `MacroOpaqueAllocation.ql`, which recovers all three
 *      ground-truth lines and matches the syntactic rule's 3.
 *
 * WHAT REMAINS A REAL WIN: sinks that are ordinary CALLS with an explicit size
 * argument — `with_capacity`, `reserve`, `resize`. Those are visible, and taint
 * reaches them ACROSS FUNCTIONS. Verified on the fixture with known answers: the
 * query reports the size at `Vec::with_capacity(n)` where `n` came from a helper's
 * RETURN VALUE, from a STRUCT FIELD, and from a struct field read inside a DIFFERENT
 * TYPE's method — three shapes cls-alloc can only reach with its shape-only tier 2,
 * i.e. with no source evidence at all. Its own header says the source-connected form
 * "occurs once in 12 crates"; on the fixture it is 1 of 4 for the syntactic rule and
 * 4 of 4 here. It also stays silent on the capped variant, and its per-value
 * `BarrierGuard` does not have cls-alloc's "unrelated cap in the same function
 * silences everything" hole.
 */

import rust
import codeql.rust.dataflow.DataFlow
import codeql.rust.dataflow.TaintTracking
import codeql.rust.security.UncontrolledAllocationSizeExtensions
import RipRust

/**
 * Gets the SYNTACTIC name of the callee.
 *
 * `Call.getTargetName()` needs `getStaticTarget()` to resolve, and measured on
 * image-png it does NOT resolve `Vec::with_capacity` (0 hits, against 2 occurrences
 * in the source) even though it resolves `index`, `new`, `into` and `unwrap` in the
 * thousands — std associated functions on a type with an allocator generic
 * (`impl<T, A: Allocator> Vec<T, A>`) come back unresolved. Requiring resolution here
 * would silently delete the entire sink set, so the name is taken from the syntax and
 * resolution is used only where it adds discrimination (see TypeDisambiguation.ql).
 */
string calleeName(Call c) {
  result = c.(MethodCallExpr).getIdentifier().getText()
  or
  result = c.(CallExpr).getFunction().(PathExpr).getPath().getSegment().getIdentifier().getText()
}

/**
 * A parameter that carries attacker-controlled bytes into the crate.
 *
 * This is the parser threat model, and it is the substantive difference from the
 * built-in query. A codec's untrusted input is its own API surface.
 */
class ByteInputParameter extends DataFlow::Node {
  ByteInputParameter() {
    exists(Param p, Function f |
      p = this.asParameter() and
      p = f.getParamList().getAParam() and
      isProductionCrateCode(f) and
      // Structural, not `toString()`: a `&[u8]` parameter's TypeRepr prints as the bare
      // string "RefTypeRepr" (measured: 173 of 468 image-png params), so a text test on
      // it matches nothing. `mentionsIdent` walks the type subtree instead and covers
      // `&[u8]`, `&mut [u8]`, `Vec<u8>`, `Cow<'_, [u8]>` and `impl Read` alike.
      mentionsIdent(p.getTypeRepr(), "^(u8|Bytes|BytesMut|Read|BufRead|Buf)$")
    )
  }
}

/** A call whose result is a number decoded out of bytes. */
class ByteDecode extends DataFlow::Node {
  ByteDecode() {
    exists(Call c |
      this.asExpr() = c and
      isProductionCrateCode(c) and
      calleeName(c)
          .regexpMatch("(from_(be|le|ne)_bytes|read_u(8|16|24|32|64|128)|read_i(8|16|32|64)|" +
              "read_uint|read_int|get_u(8|16|32|64)|get_i(8|16|32|64)|" +
              "read_exact|read_to_end|read_be_.*|read_le_.*)")
    )
  }
}

/** Indexing into a byte buffer: `buf[i]`, `hdr[3]`. */
class ByteIndexRead extends DataFlow::Node {
  ByteIndexRead() {
    exists(IndexExpr ie |
      this.asExpr() = ie and
      isProductionCrateCode(ie)
    )
  }
}

/** Allocation sinks that are ordinary calls, and therefore actually extractable. */
class CallShapedAllocSink extends DataFlow::Node {
  string kind;

  CallShapedAllocSink() {
    exists(Call c, string name |
      isProductionCrateCode(c) and
      name = calleeName(c)
    |
      // size-carrying argument 0
      name =
        [
          "with_capacity", "with_capacity_in", "reserve", "reserve_exact",
          "try_reserve", "try_reserve_exact", "resize", "resize_with", "from_elem",
          "repeat", "set_len", "alloc", "alloc_zeroed", "from_size_align",
          "from_size_align_unchecked"
        ] and
      this.asExpr() = c.getPositionalArgument(0) and
      kind = name
    )
  }

  string getKind() { result = kind }
}

/**
 * A decompression whose OUTPUT size is a function of the input, with no length field
 * anywhere. cls-alloc gives this its own rule for the same reason.
 */
class ImplicitSizeSink extends DataFlow::Node {
  ImplicitSizeSink() {
    exists(Call c |
      isProductionCrateCode(c) and
      calleeName(c) =
        [
          "decompress_to_vec", "decompress_to_vec_zlib", "decompress_to_vec_with_limit",
          "decompress_to_vec_zlib_with_limit", "read_to_end", "read_to_string",
          "decode_all", "inflate", "uncompress"
        ] and
      this.asExpr() = c.getAnArgument()
    )
  }
}

module AllocConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof ByteInputParameter or
    source instanceof ByteDecode or
    source instanceof ByteIndexRead
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CallShapedAllocSink or
    sink instanceof ImplicitSizeSink
  }

  /**
   * The upper-bound-check barrier from the shipped extension library.
   *
   * This is where CodeQL is strictly better than cls-alloc's cap test, which is
   * textual and function-wide: cls-alloc's own header records that "an UNRELATED
   * cap-shaped comparison in the same function silences the macro rule completely
   * ... the single largest recall hole in the file". A `BarrierGuard` is per-value
   * and per-branch, so an unrelated `if other > MAX_OTHER` does not silence
   * anything.
   */
  predicate isBarrier(DataFlow::Node barrier) {
    barrier instanceof UncontrolledAllocationSize::Barrier
  }
}

module AllocFlow = TaintTracking::Global<AllocConfig>;

import AllocFlow::PathGraph

from AllocFlow::PathNode source, AllocFlow::PathNode sink
where AllocFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "allocation size flows from parsed bytes with no upper-bound guard on the path @ " +
    sink.getNode().getLocation().getFile().getRelativePath() + ":" +
    sink.getNode().getLocation().getStartLine(), source.getNode(), "parsed byte input"
