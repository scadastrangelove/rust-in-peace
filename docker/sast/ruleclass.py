#!/usr/bin/env python3
"""ruleclass.py — the single source of truth for "what is this rule ABOUT, and what may it do?".

Shared by `normalize.py` (cell formation) and `prune_report.py` (the ledger) so the two can never
drift into disagreeing taxonomies.

## Two orthogonal questions

**ROLE** — what the rule is allowed to do downstream:

  primary        may OPEN a cell. Security-relevant classes, plus anything unrecognized.
  enumerator     U1 worklists (rip-e*). Feed the finder a SITE INVENTORY; they must not open cells —
                 `rip-e003-numeric-cast` alone fires 1 103 times across the corpus and would drown
                 every cell it touched. Completeness is their success criterion, not precision.
  corroborating  may NOT open a cell, but is ATTACHED to cells opened by others, as context.

**CLASS** — the bug family, used as the cell key.

## The critical rule: corroborating ≠ deleted

Nothing is ever removed from `hits.jsonl`. A "style" lint can still be the tell that strengthens a
real finding — `redundant_pub_crate` next to an unsafe block is a wider attack surface than the
author intended — so corroborating hits stay visible inside the cell they fall into. What changes is
only what is allowed to *open* a cell and spend an agent's attention.

## Five lints that look like style and are not (audited 2026-07-28)

These were caught while reviewing the first classifier draft, which would have demoted all five:

  * `missing_panics_doc`      — fires because clippy PROVED the fn can panic. That is a panic-surface
                                detector wearing a documentation lint's name.
  * `missing_safety_doc`      — fires on an `unsafe fn`. An unsafe-surface signal, not a docs nit.
  * `implicit_hasher`         — a HashMap with the default hasher and attacker-controlled keys is
                                HashDoS. Algorithmic-complexity attack, squarely in scope.
  * `significant_drop_tightening` — a lock guard held longer than needed: concurrency, and adjacent
                                to the "guard held across .await" class the Rust review calls out.
  * `non_local_effect_before_unhandled_error` (dylint) — state mutated, then an error returned. This
                                is the broken-invariant / panic-safety family; the highest-value
                                dylint rule we have and the only one with real volume.

The pattern in all five: **a rule named for its remedy rather than its trigger.** When auditing a
classifier, read what makes the rule FIRE, never what it asks you to do about it.
"""
from __future__ import annotations

import re

# ── explicit overrides, checked FIRST. Every entry needs a reason in the docstring above. ──────────
OVERRIDES: dict[str, tuple[str, str]] = {
    # ── CodeQL (host phase), classified from a measured run over 6 corpus databases, 2026-08-01 ──
    # Unknown ids default to ("primary", "unclassified"), so every CodeQL rule opened cells on first
    # contact. Measured volume across image-png / lopdf / miniz_oxide / msgpack-rust / object /
    # quick-xml: type-disambiguation 996, alloc-macro-opaque 107, recursion-cycle 54,
    # pop-no-dominating-guard 13, alloc-sized-by-parsed-length 7.
    #
    # `type-disambiguation` alone is 66 % of CodeQL's output — ~166 hits per crate, which by E7c's
    # own density/discrimination relation (32.5 hits/crate → 0.5 %) is squarely enumerator territory.
    # It is also the exact CodeQL counterpart of `rip-e003-numeric-cast` (counter width / numeric
    # casts), which is already an enumerator by prefix. Same shape, same role — otherwise it drowns
    # the cells it lands in and buys the volume without the signal.
    "rip/rust/type-disambiguation":        ("enumerator", "u1-worklist"),
    # The three classes CodeQL is R for and ast-grep is not (no CFG, no call graph, opaque macros).
    # These are exactly why the engine is worth a separate phase, so they open cells.
    "rip/rust/pop-no-dominating-guard":    ("primary", "index-surface"),
    "rip/rust/recursion-cycle":            ("primary", "resource"),
    "rip/rust/alloc-macro-opaque":         ("primary", "resource"),
    "rip/rust/alloc-sized-by-parsed-length": ("primary", "resource"),

    "clippy::missing_panics_doc":       ("primary", "panic-surface"),
    "clippy::missing_safety_doc":       ("primary", "unsafe"),
    "clippy::undocumented_unsafe_blocks": ("primary", "unsafe"),
    "clippy::implicit_hasher":          ("primary", "algorithmic-complexity"),
    "clippy::significant_drop_tightening": ("primary", "concurrency"),
    "non_local_effect_before_unhandled_error": ("primary", "panic-safety"),
    "await_holding_span_guard":         ("primary", "concurrency"),
    "non_thread_safe_call_in_test":     ("corroborating", "test-only"),
    "basic_dead_store":                 ("corroborating", "style/idiom"),
    "crate_wide_allow":                 ("corroborating", "lint-suppression"),
    "abs_home_path":                    ("corroborating", "style/idiom"),
    # Named for the remedy, triggered by nothing dangerous: keep as context.
    "clippy::must_use_candidate":       ("corroborating", "style/idiom"),
    "clippy::return_self_not_must_use": ("corroborating", "style/idiom"),
    # Visibility wider than needed — real, but weak on its own. Context, not a cell opener.
    "clippy::redundant_pub_crate":      ("corroborating", "visibility"),
    # ── promoted/demoted by the h2 judge pass, 2026-07-28 (evidence in the bring-up case study) ──
    # A large Err variant inflates every Result on its path — including per-stream async state
    # machines on an attacker-reachable parse path. Resource amplification, not a style nit:
    # h2's Oversize(T) variant measured ≥288 bytes at proto/streams/recv.rs:74.
    "clippy::result_large_err":         ("primary", "resource"),
    # Judged non-security ON EVIDENCE (sites read, not assumed). `checked_conversions` in
    # particular fires where a manual check IS already present — it asks you to spell it
    # differently, so its firing is proof the check exists, not that it is missing.
    "clippy::if_not_else":              ("corroborating", "style/idiom"),
    "clippy::useless_let_if_seq":       ("corroborating", "style/idiom"),
    "clippy::branches_sharing_code":    ("corroborating", "style/idiom"),
    "clippy::struct_field_names":       ("corroborating", "naming"),
    "clippy::question_mark":            ("corroborating", "style/idiom"),
    "clippy::missing_fields_in_debug":  ("corroborating", "documentation"),
    "clippy::checked_conversions":      ("corroborating", "style/idiom"),
    "clippy::type_repetition_in_bounds": ("corroborating", "style/idiom"),
}

# ── security-relevant families: may open a cell. Checked before the style list — a false
#    "security" costs triage time, a false "style" silently drops a real finding. ──────────────────
SECURITY: list[tuple[re.Pattern[str], str]] = [
    # MUST precede the panic-surface row. `unwrap_or`, `unwrap_or_else` and `unwrap_or_default` are
    # TOTAL — they cannot panic — but they share the token `unwrap` with the ones that can, so the
    # substring rule below swallowed all three into `panic-surface`.
    #
    # Measured in E9: five independent reachability judges spent budget correcting the label, and two
    # of them returned `reachability: no` on that basis alone ("cls-error-swallow-unwrap-or-else
    # mis-fired: no panic site exists here"). A wrong CLASS is not cosmetic — it sets the cell's
    # class prior, which the skill says to rank by, and it is what the judge is asked to reason about.
    #
    # The docstring above warns against naming a rule for its remedy. This is the sibling failure:
    # classifying a rule by a TOKEN it happens to contain rather than by the construct it matches.
    (re.compile(r"unwrap_or|error[-_]swallow|let[-_]underscore|match[-_]wildcard"), "error-swallow"),
    (re.compile(r"unwrap|expect_used|\bpanic|unreachable|todo|unimplemented"), "panic-surface"),
    (re.compile(r"indexing_slicing|get_unchecked|slice_|out_of_bounds"), "index-surface"),
    (re.compile(r"arithmetic|overflow|underflow|wrapping|modular|div_by|zero"), "arithmetic"),
    (re.compile(r"cast_|as_conversions|truncat|sign_loss|precision_loss|lossless|from_over_into"),
     "conversion"),
    (re.compile(r"unsafe|transmute|uninit|ptr_|raw_|mem_forget|mem_replace|cast_ref|align"), "unsafe"),
    (re.compile(r"await|mutex|lock|atomic|thread|deadlock|rc_buffer|rc_mutex|send|sync"),
     "concurrency"),
    (re.compile(r"command|process|exit|env_|path_|fs_|tempfile|permissions|create_dir"),
     "os-interaction"),
    (re.compile(r"crypto|hash|rand|secret|password|token|insecure|ssl|tls|verify|cert|weak"),
     "crypto-trust"),
    (re.compile(r"rustsec|advisory|yanked|RUSTSEC"), "dependency"),
    (re.compile(r"recursi|unbounded|with_capacity|reserve|alloc|read_to_end|collect_into"),
     "resource"),
    (re.compile(r"serde|deserial|decode|from_str|parse_"), "deser-parse"),
]

# ── definitionally non-security: cannot express a security defect. Corroborating only. ────────────
NON_SECURITY: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"doc_markdown|missing_errors_doc|missing_docs|doc_link|empty_line_after|"
                r"tabs_in_doc|doc_lazy"), "documentation"),
    (re.compile(r"semicolon|unreadable_literal|separated_literal|inline_always|uninlined_format|"
                r"write_with_newline|writeln_empty|literal_string|mixed_case"), "formatting"),
    (re.compile(r"use_self|elidable|needless_lifetimes|module_name_repetitions|wildcard_imports|"
                r"enum_glob_use|items_after_statements|single_char_pattern|unnecessary_wraps|"
                r"struct_excessive_bools|too_many_lines|match_same_arms|option_if_let_else|"
                r"single_match_else|redundant_closure|manual_let_else|explicit_iter_loop|"
                r"missing_inline_in_public_items|missing_const_for_fn|redundant_else|"
                r"ignored_unit_patterns|default_trait_access|match_bool|needless_pass_by|"
                r"trivially_copy_pass_by_ref|unused_self|should_implement_trait"), "style/idiom"),
    (re.compile(r"similar_names|upper_case_acronyms|used_underscore|min_ident_chars|"
                r"many_single_char"), "naming"),
]


def classify(rule_id: str) -> tuple[str, str]:
    """rule id -> (role, class). role ∈ primary | enumerator | corroborating."""
    rule = rule_id.split(".")[-1] if rule_id.startswith("opt.") else rule_id
    if rule in OVERRIDES:
        return OVERRIDES[rule]
    if rule.startswith("rip-e"):
        return "enumerator", "u1-worklist"
    for pat, cls in SECURITY:
        if pat.search(rule):
            return "primary", cls
    for pat, cls in NON_SECURITY:
        if pat.search(rule):
            return "corroborating", cls
    # Unrecognized stays PRIMARY. A classifier that quietly demotes what it does not know is the
    # same defect as a status field describing the wrong artifact (LESSONS L52).
    return "primary", "unclassified"
