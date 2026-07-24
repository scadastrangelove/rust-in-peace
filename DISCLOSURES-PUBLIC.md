# rust-in-peace — Coordinated Disclosures

[rust-in-peace](README.md) is an AI-assisted vulnerability-research pipeline for Rust codebases,
forked from Anthropic's [defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness).
This page tracks every vulnerability reported to a third-party project as a result of that research,
its current status, and — once a report has moved to a public issue, a merged fix, or a vendor-published
advisory — a short summary of the finding.

Reporter of record: Sergey Gordeychik ([@scadastrangelove](https://github.com/scadastrangelove)).

## Disclosure policy

- **Private channel first, when one exists.** If a project supports GitHub's private vulnerability
  reporting or publishes a security contact, we use it. Otherwise we default to a public issue (plus a
  pull request, where a fix is ready) — most Rust crates have no dedicated security channel, and a
  public issue gets a faster, better-tracked response than a cold email.
- **No exploit details before a fix ships.** Advisories sent through a private channel are listed here
  by ID and status only, until the vendor publishes the advisory themselves. We do not describe the
  vulnerability class, mechanism, or proof-of-concept for anything still unfixed and unpublished.
- **Cadence.** A private report gets a follow-up at ~14 days if silent, and moves toward public
  disclosure at ~90 days if the vendor remains unresponsive — standard coordinated-disclosure timing.
- **Standing re-checks.** Closures we don't agree with are re-verified against current source on a
  delay rather than contested in the moment; if a vendor fixes something independently later, this page
  is updated to reflect that, without asking for credit.

## Summary

| | |
|---|---:|
| Reports filed | 51 |
| Resolved (fixed / merged) | 12 |
| Open — awaiting vendor action | 25 |
| Closed — disputed, or not a vulnerability | 5 |
| Private advisories pending vendor publication | 9 |

## Public disclosures

Findings sent as (or since converted to) a public issue, pull request, or vendor-published advisory.
"Summary" reflects only what's already visible at the linked report — nothing here goes beyond that.

| Target | Reported | Report | Severity | Status | Summary |
|---|---|---|---|---|---|
| actix-web | 2026-07-23 | [#4161](https://github.com/actix/actix-web/issues/4161) | Low | Open | Chunked-transfer-encoding parser accepts non-conformant chunk-size terminators (hardening; not a demonstrated smuggling exploit) |
| Chromium / Skia (vendored `image` fork) | 2026-07-22 | [issue 537617321](https://issues.chromium.org/issues/537617321) | Low | Open — awaiting triage | Unbounded allocation while parsing an embedded BMP color-profile size field |
| fdeflate | 2026-07-19 | [#83](https://github.com/image-rs/fdeflate/issues/83) | Low | Closed — severity disputed by vendor; our own reassessment concurred | Huffman-table-rebuild cost scaling on crafted input |
| gimli | 2026-07-19 | [#898](https://github.com/gimli-rs/gimli/issues/898) | Low-Medium | Open | Quadratic-time attribute parsing via zero-byte DWARF forms |
| httparse | 2026-07-19 | [#222](https://github.com/seanmonstar/httparse/issues/222) / [PR #223](https://github.com/seanmonstar/httparse/pull/223) | Low-Medium | Open | A whitespace-only header line silently truncates the entire header block, under an opt-in leniency flag |
| image | 2026-07-19 | [#3076](https://github.com/image-rs/image/issues/3076) | High | Open | AVIF decode proceeds before configured memory limits are enforced |
| image | 2026-07-19 | [#3077](https://github.com/image-rs/image/issues/3077) | High | Resolved | WebP animation decode bypassed configured memory limits |
| image | 2026-07-19 | [#3078](https://github.com/image-rs/image/issues/3078) | Medium | Resolved | Memory limits not enforced on one decode path |
| image | 2026-07-19 | [#3079](https://github.com/image-rs/image/issues/3079) | High | Resolved | GIF decode limits gap, same root cause as #3077 |
| image | 2026-07-19 | [#3080](https://github.com/image-rs/image/issues/3080) | High | Resolved | APNG decode limits gap, same root cause as #3077 |
| image | 2026-07-19 | [#3081](https://github.com/image-rs/image/issues/3081) | High | Closed — disputed; independently reconfirmed present in current source | `DynamicImage::from_decoder` allocates without consulting configured memory limits |
| image | 2026-07-19 | [#3082](https://github.com/image-rs/image/issues/3082) | High | Resolved | HDR decode limits gap, same root cause as #3077 |
| image | 2026-07-19 | [#3083](https://github.com/image-rs/image/issues/3083) | Low-Medium | Open — proposed fix declined by vendor; underlying issue not disputed | `resize_to_fill` overshoots on an extreme aspect ratio |
| image | 2026-07-19 | [#3084](https://github.com/image-rs/image/issues/3084) / [PR #3085](https://github.com/image-rs/image/pull/3085) | Medium | Open — positively reviewed, blocked on CI | AVIF alpha-plane data corruption |
| lopdf | 2026-07-19 | [#532](https://github.com/J-F-Liu/lopdf/issues/532) / [PR #533](https://github.com/J-F-Liu/lopdf/pull/533) | Low | Resolved (2026-07-20) | Four reachable panics decoding crafted PDFs |
| lopdf | 2026-07-19 | [#530](https://github.com/J-F-Liu/lopdf/issues/530) / [PR #531](https://github.com/J-F-Liu/lopdf/pull/531) | Low | Resolved (2026-07-20) | Unbounded recursion walking the post-load document graph |
| miniz_oxide | 2026-07-19 | [#198](https://github.com/Frommi/miniz_oxide/issues/198) / [PR #199](https://github.com/Frommi/miniz_oxide/pull/199) | Medium-High | Open | Huffman-table-rebuild cost decoupled from decompressed output size |
| miniz_oxide | 2026-07-19 | [#200](https://github.com/Frommi/miniz_oxide/issues/200) | Low | Open | Logic error in a bounds comparison (performance-only) |
| miniz_oxide | 2026-07-19 | [#201](https://github.com/Frommi/miniz_oxide/issues/201) | Medium | Open | Non-default feature bypasses decoder state-machine invariants |
| miniz_oxide | 2026-07-19 | [#202](https://github.com/Frommi/miniz_oxide/issues/202) | Low | Open | Documentation and integer-truncation hardening notes |
| ntex | 2026-07-23 | [#944](https://github.com/ntex-rs/ntex/issues/944) | Low | Open | Same chunked-encoding leniency class as actix-web #4161, independently implemented |
| ntex | 2026-07-23 | [#945](https://github.com/ntex-rs/ntex/issues/945) | Low | Open | `GET` + `Transfer-Encoding` on HTTP/1.0 framed as bodiless |
| ntex | 2026-07-23 | [#946](https://github.com/ntex-rs/ntex/issues/946) / [PR #947](https://github.com/ntex-rs/ntex/pull/947) | Low-Medium | Resolved (2026-07-24) | Per-connection byte counter never reset per message, causing spurious request-too-large errors |
| object | 2026-07-18 | [#950](https://github.com/gimli-rs/object/issues/950) / [PR #951](https://github.com/gimli-rs/object/pull/951) | Low-Medium | Open | Zstd-compressed section decompression bypasses its own size cap |
| object | 2026-07-18 | [#952](https://github.com/gimli-rs/object/issues/952) / [PR #953](https://github.com/gimli-rs/object/pull/953) | Low-Medium | Open | Mach-O exports-trie shared-subtree parsing scales exponentially |
| png | 2026-07-19 | [#696](https://github.com/image-rs/image-png/issues/696) / [PR #697](https://github.com/image-rs/image-png/pull/697) | Medium-High | Open | Decompression-bomb hardening for zTXt/iTXt chunks |
| png | 2026-07-19 | [#694](https://github.com/image-rs/image-png/issues/694) | Medium | Resolved | PLTE-chunk-length panic (fixed independently before this report) |
| png | 2026-07-19 | [#692](https://github.com/image-rs/image-png/issues/692) | Medium | Closed — disputed; independently reconfirmed present in current source | `output_buffer_size()` doesn't consult configured memory limits |
| png | 2026-07-19 | [#699](https://github.com/image-rs/image-png/issues/699) / [PR #703](https://github.com/image-rs/image-png/pull/703) | Low-Medium | Open | APNG interlaced-frame stride miscalculation |
| png | 2026-07-19 | [#700](https://github.com/image-rs/image-png/issues/700) / [PR #702](https://github.com/image-rs/image-png/pull/702) | Low-Medium | Open | Chunk-ordering validation gap |
| png | 2026-07-19 | [#698](https://github.com/image-rs/image-png/issues/698) | Low | Closed — not a vulnerability (documented, required behavior) | Adam7 interlacing buffer-reuse report |
| png | 2026-07-19 | [#701](https://github.com/image-rs/image-png/issues/701) | Low | Closed — not a vulnerability (works as documented) | ICC-profile error handling |
| quick-xml | 2026-07-19 | [#977](https://github.com/tafia/quick-xml/issues/977) / [PR #979](https://github.com/tafia/quick-xml/pull/979) | Low-Medium | Resolved (2026-07-20) | Namespace-resolver depth counter overflow (panic and scope misresolution) |
| quick-xml | 2026-07-19 | [#978](https://github.com/tafia/quick-xml/issues/978) / [PR #982](https://github.com/tafia/quick-xml/pull/982) | Low-Medium | Open | Serde deserializer has no recursion-depth cap |
| quick-xml | 2026-07-19 | [#980](https://github.com/tafia/quick-xml/issues/980) | Low-Medium | Open | Namespace-prefix resolution scales quadratically with nesting depth |
| rmp-serde | 2026-07-20 | [#381](https://github.com/3Hren/msgpack-rust/issues/381) / [PR #382](https://github.com/3Hren/msgpack-rust/pull/382) | Medium | Open | Recursion-depth guard doesn't cover all deserialization entry points |
| ttf-parser | 2026-07-20 | [#218](https://github.com/harfbuzz/ttf-parser/issues/218) / [PR #222](https://github.com/harfbuzz/ttf-parser/pull/222) | Medium | Open | CFF2 operand-stack underflow |
| ttf-parser | 2026-07-20 | [#219](https://github.com/harfbuzz/ttf-parser/issues/219) / [PR #223](https://github.com/harfbuzz/ttf-parser/pull/223) | Low | Open | Variation-axis-mapping integer overflow |
| ttf-parser | 2026-07-20 | [#220](https://github.com/harfbuzz/ttf-parser/issues/220) / [PR #224](https://github.com/harfbuzz/ttf-parser/pull/224) | High | Open | Composite-glyph shared-subtree parsing scales exponentially |
| ttf-parser | 2026-07-20 | [#221](https://github.com/harfbuzz/ttf-parser/issues/221) / [PR #225](https://github.com/harfbuzz/ttf-parser/pull/225) | High | Open | COLR paint-graph shared-subtree parsing scales exponentially |
| x509-parser | 2026-07-19 | [#251](https://github.com/rusticata/x509-parser/issues/251) / [PR #252](https://github.com/rusticata/x509-parser/pull/252) | Low | Resolved (2026-07-22) | `ASN1Time` arithmetic panics instead of returning `None` on overflow |
| zune-jpeg | 2026-07-18 | reported via private channel | Low | Resolved upstream (fix predates this report; not yet in a published crate release) | Reachable panic decoding a crafted progressive JPEG |

## Pending disclosures (private)

Reported through a private vulnerability-disclosure channel and not yet published by the vendor. Listed
here by advisory ID and status only — no technical detail is disclosed before the vendor publishes.

| Target | Reported | Advisory ID | Status |
|---|---|---|---|
| actix-web | 2026-07-23 | [GHSA-rmg3-w467-r3hg](https://github.com/actix/actix-web/security/advisories/GHSA-rmg3-w467-r3hg) | Under vendor review |
| ciborium | 2026-07-19 | [GHSA-gg22-wcqw-grr3](https://github.com/enarx/ciborium/security/advisories/GHSA-gg22-wcqw-grr3) | Under vendor review |
| ciborium | 2026-07-19 | [GHSA-5857-62v3-27wr](https://github.com/enarx/ciborium/security/advisories/GHSA-5857-62v3-27wr) | Under vendor review |
| ciborium | 2026-07-19 | [GHSA-qxw2-g7wc-7h4j](https://github.com/enarx/ciborium/security/advisories/GHSA-qxw2-g7wc-7h4j) | Under vendor review |
| ciborium | 2026-07-19 | [GHSA-gpv3-7pvc-5937](https://github.com/enarx/ciborium/security/advisories/GHSA-gpv3-7pvc-5937) | Under vendor review |
| gitoxide | 2026-07-22 | [GHSA-pmm9-4h7q-24c8](https://github.com/GitoxideLabs/gitoxide/security/advisories/GHSA-pmm9-4h7q-24c8) | Accepted by vendor — fix in progress |
| quinn-proto | 2026-07-23 | [GHSA-hmxj-32vh-65vr](https://github.com/quinn-rs/quinn/security/advisories/GHSA-hmxj-32vh-65vr) | Accepted by vendor — fix in progress |
| rustls | 2026-07-23 | [GHSA-j99h-2h74-pcqx](https://github.com/rustls/rustls/security/advisories/GHSA-j99h-2h74-pcqx) | Under vendor review |
| rustls | 2026-07-23 | [GHSA-4xwv-fw6q-5gvr](https://github.com/rustls/rustls/security/advisories/GHSA-4xwv-fw6q-5gvr) | Under vendor review |

## Notes

- Severity labels are qualitative (Low / Medium / High), reflecting our own assessment at time of
  report — not a formal CVSS score, and not a substitute for the vendor's own rating where one exists.
- "Resolved" means a fix has been merged or independently confirmed present in the target's current
  source; it does not always mean a new version has been published to crates.io. Where that distinction
  matters (e.g. zune-jpeg), it's noted in the Summary column.
- A closure marked "disputed" reflects our own re-verification against the target's current source, not
  a claim that the vendor acted in bad faith — vendors regularly and reasonably assess scope and
  priority differently than an external reporter.
- This list is updated as reports change status. Last updated: 2026-07-24.
