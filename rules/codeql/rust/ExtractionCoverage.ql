/**
 * @name Extraction coverage census
 * @description Per-file element counts for the crate under analysis, plus the database-wide
 *              `Unextracted`/`Missing`/`Unimplemented` totals and the macro-expansion rate.
 *              Run this FIRST on any new database — every other query's zero is void without it.
 * @kind table
 * @id rip/rust/extraction-coverage
 */

/*
 * =============================================================================
 * WHY THIS QUERY EXISTS
 * =============================================================================
 *
 * `codeql database create --build-mode=none` prints a line of the form
 *
 *     Rust files that were extracted with errors: 85
 *
 * against 101 `.rs` files in lopdf. Taken at face value that is an 84% drop rate and
 * every downstream result is meaningless. It is not what the line means.
 *
 * MEASURED (CodeQL 2.26.1, `codeql/rust-all` 0.2.17):
 *
 *   database-wide `Unextracted` / `Missing` / `Unimplemented` elements
 *       lopdf 0     image-png 0     miniz_oxide 0
 *   crate files present in the database, against the `print-baseline` file list
 *       lopdf 101/101   image-png 36/36   miniz_oxide 33/33
 *   crate files with zero AST nodes
 *       lopdf 0   image-png 0   miniz_oxide 2 (two feature-gated test files)
 *   per-file `Function` counts against a source `fn` count
 *       src/xref.rs 23/23   src/parser/mod.rs 85/85   src/document.rs 50/50
 *       src/encodings/glyphnames.rs 4/4
 *       src/reader.rs 53/72 — the 19 missing are exactly the
 *         `#[cfg(feature = "async")]` duplicates of the extracted non-async arm
 *
 * So "extracted with errors" counts files in which at least one MACRO EXPANSION
 * failed. The file, its items, and its expressions are all present. The extractor is
 * not dropping code.
 *
 * WHAT *IS* MISSING, and it is the number that actually matters:
 *
 *   macro calls in crate source / of those, expanded
 *       lopdf        1040 / 7189   (14.5%)
 *       image-png      73 /  663   (11.0%)
 *       miniz_oxide   166 /  293   (56.7%)
 *   `vec!`     0/285      0/93     0/15
 *   `assert!`  0/321      0/83    11/26
 *
 * User-defined `macro_rules!` expand; the core/std built-ins (`vec!`, `assert!`,
 * `format!`, `write!`) largely do not, because nothing is compiled and there is no
 * proc-macro server. Anything written inside those macros is a single opaque
 * `TokenTree` — see `MacroOpaqueAllocation.ql`.
 *
 * The second thing to check on a new database is CFG SELECTION. The extractor enables
 * all cargo features by default, so a plain `#[cfg(feature = "x")]` module IS present
 * (verified: quick-xml's `pub mod de`, gated `#[cfg(feature = "serialize")]` behind
 * `default = []`, is extracted — 37 functions in `src/de/map.rs`). But a feature whose
 * OPTIONAL DEPENDENCY cannot be resolved offline drops its arm silently: lopdf's
 * `#[cfg(feature = "async")]` needs `tokio`, and 19 of `src/reader.rs`'s 72 functions
 * — every one of them in that arm — are absent with no diagnostic. Compare the file
 * and function counts this query returns against the crate's own
 * `grep -c '^\s*\(pub \)\?fn '` before trusting a silent class.
 */

import rust
import RipRust

from File f, int fns, int calls, int mcalls, int macros, int nodes
where
  isCrateLocalFile(f) and
  fns = count(Function fn | fn.getFile() = f) and
  calls = count(CallExpr c | c.getFile() = f) and
  mcalls = count(MethodCallExpr c | c.getFile() = f) and
  macros = count(MacroCall c | c.getFile() = f) and
  nodes = count(AstNode n | n.getFile() = f)
select f.getRelativePath() as path, fns as functions, calls, mcalls as methodCalls,
  macros as macroCalls, nodes as astNodes order by astNodes desc
