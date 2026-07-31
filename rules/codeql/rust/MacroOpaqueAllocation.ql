/**
 * @name Allocation with no analysable size expression
 * @description A `vec![_; n]`-family allocation whose size the extractor discarded, or a
 *              decompression whose output size is implicit in its input. In both cases
 *              there is no size expression for dataflow to reach, so this is shape-only.
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id rip/rust/alloc-macro-opaque
 * @tags security
 *       candidate-generator
 *       external/cwe/cwe-770
 *       external/cwe/cwe-789
 */

/*
 * =============================================================================
 * THIS QUERY EXISTS BECAUSE CODEQL LOSES HERE, AND SILENCE WOULD BE WORSE
 * =============================================================================
 *
 * Under `--build-mode=none` the Rust extractor does not expand `vec!`. Measured on
 * this corpus, expansion rate for `vec!` is:
 *
 *     lopdf        0 / 285
 *     image-png    0 /  93
 *     miniz_oxide  0 /  15
 *
 * An AST probe of lopdf `src/parser_aux.rs:577` — the exact line PR #533 fixed —
 * returns exactly three nodes for `vec![0_u8; field_widths[0] as usize]`:
 *
 *     MacroCall "vec!..."      TokenTree      MacroExpr
 *
 * and nothing else. `TokenTree` in the generated API (`elements/TokenTree.qll`) has
 * no text accessor and no children: it is a single opaque node carrying only a
 * location. So the size expression is not merely hard to reach, it is ABSENT. No
 * dataflow configuration can reach it and no cap can be attributed to it. That is
 * the direct explanation for `rust/uncontrolled-allocation-size` returning 0 on
 * lopdf, image-png and miniz_oxide.
 *
 * ast-grep, being textual, still has the token text and matches
 * `vec![$X; $N]`/`vec![..]` — which is how `cls-alloc.yml`'s
 * `rip-alloc-vec-repeat-uncapped` catches the pre-fix lopdf site. On this sub-class
 * the syntactic rule WINS and CodeQL loses on the ground truth.
 *
 * What this query can still do is refuse to be silent. It reports the macro CALL when
 * the enclosing function shows a byte-parsing source, so the class degrades to noisy
 * rather than blind. Under the pipeline's cost model — a false positive costs one
 * agent read, a false negative is permanent and silent — that is the right degradation.
 *
 * THE SECOND SHAPE HERE HAS THE SAME PROBLEM FOR A DIFFERENT REASON. png's zTXt/iTXt
 * bomb (`image-png/src/text_metadata.rs:309/482/570`,
 * `fdeflate::decompress_to_vec(v)`) has NO length field anywhere — the output size is a
 * function of the compressed input. `cls-alloc.yml` gives it its own rule
 * (`rip-decompress-output-unbounded`) for exactly that reason, and measured on
 * image-png the taint-tracking query finds it 0 times while the syntactic rule finds it
 * 3 times: the compressed bytes arrive through a struct field the decoder populated
 * several frames earlier, and demanding a connected source is the wrong question when
 * there is no size to connect to. So it is reported here on shape, like the macros.
 *
 * DELIBERATELY NO CAP SUPPRESSION. cls-alloc's macro rule degrades its cap test to
 * "does the enclosing function contain ANY cap-shaped comparison", and its header
 * records the consequence: "an UNRELATED cap-shaped comparison in the same function
 * silences the macro rule completely ... the single largest recall hole in the file".
 * CodeQL cannot do better here — attributing a cap to the size requires knowing what
 * the size IS — so rather than reproduce the hole with a dominance test that looks
 * principled and is not, no suppression is applied at all. If the operator wants the
 * quieter behaviour, that belongs downstream in the judge, not here.
 */

import rust
import RipRust

/** Gets the syntactic name of the callee (see `AllocParsedLength.ql` for why not `getTargetName`). */
string calleeName(Call c) {
  result = c.(MethodCallExpr).getIdentifier().getText()
  or
  result = c.(CallExpr).getFunction().(PathExpr).getPath().getSegment().getIdentifier().getText()
}

/** An allocation-shaped macro whose size argument the extractor discards. */
class AllocMacroCall extends MacroCall {
  AllocMacroCall() {
    this.getPath().toString() = ["vec", "...::vec", "smallvec", "bytes", "arrayvec"]
  }
}

/**
 * Holds if `f` reads bytes it did not produce — the parser threat model, same as
 * `AllocParsedLength.ql`.
 */
predicate parsesBytes(Function f) {
  exists(Param p |
    p = f.getParamList().getAParam() and
    mentionsIdent(p.getTypeRepr(), "^(u8|Bytes|BytesMut|Read|BufRead|Buf)$")
  )
  or
  exists(Call c |
    getEnclosingFunction(c) = f and
    calleeName(c)
        .regexpMatch("(from_(be|le|ne)_bytes|read_u(8|16|24|32|64|128)|read_i(8|16|32|64)|" +
        "read_exact|read_to_end|get_u(8|16|32|64)|read_uint|read_int)")
  )
  or
  exists(IndexExpr ie | getEnclosingFunction(ie) = f)
}

/**
 * A decompression whose OUTPUT size is implicit in its input, so no size expression
 * exists to analyse. Reported unconditionally in production code: unlike the macro
 * leg there is nothing to gate on, and a bounded variant is spelled with an explicit
 * limit argument, which is excluded by name below.
 */
class ImplicitSizeDecompression extends Call {
  ImplicitSizeDecompression() {
    calleeName(this) =
      [
        "decompress_to_vec", "decompress_to_vec_zlib", "read_to_end", "read_to_string",
        "decode_all", "inflate", "uncompress", "decompress"
      ] and
    // the `_bounded` / `_with_limit` variants take an explicit cap and are the FIX,
    // not the defect — cf. image-png `decompress_to_vec_bounded(&v[..], limit)`
    not calleeName(this).matches(["%_bounded", "%_with_limit"])
  }
}

from AstNode at, string msg
where
  isProductionCrateCode(at) and
  (
    exists(AllocMacroCall mc, Function f |
      at = mc and
      f = getEnclosingFunction(mc) and
      parsesBytes(f) and
      msg =
        "allocation macro `" + mc.getPath().toString() +
          "!` in a byte-parsing function; its size expression is not extracted " +
          "(opaque TokenTree) so no dataflow or cap analysis applies, in " + qualifiedName(f)
    )
    or
    exists(ImplicitSizeDecompression d, Function f |
      at = d and
      f = getEnclosingFunction(d) and
      msg =
        "decompression with no explicit output limit; the output size is a function of the " +
          "input, so there is no size expression to trace, in " + qualifiedName(f)
    )
  )
select at, msg + " @ " + at.getFile().getRelativePath() + ":" + at.getLocation().getStartLine()
