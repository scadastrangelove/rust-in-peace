# Threat Model: dr_libs (dr_wav, dr_flac)

## 1. System context

dr_libs is a set of single-header, public-domain C audio decoders. The two headers in scope at pinned commit `fb1b2dfc585c` are `dr_wav.h` (~9k LOC) and `dr_flac.h` (~12k LOC). Each is a pure parser: a caller hands it untrusted bytes via `drwav_init_memory*` / `drflac_open_memory*` (or the `_file` variants) and receives decoded PCM frames plus parsed container metadata. There is no network layer, no authentication, and no internal privilege boundary; the only trust boundary is between attacker-supplied bytes and the embedding application's address space.

The library is designed to be vendored: consumers copy the header into their own tree and compile it directly into their binary. Typical embedders are game engines, media players, DAWs, and server-side transcoding pipelines, any of which may accept audio files from untrusted sources (user uploads, network streams, attachments). Parsing runs in-process at the embedder's privilege level, in manually managed C with pointer arithmetic and `malloc`/`realloc` sizing driven by fields read from the input.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| host process integrity | Control-flow and memory integrity of the embedding application; compromise yields code execution at the embedder's privilege | critical |
| adjacent process memory | Heap and stack data belonging to the embedder that sits near decoder buffers (keys, tokens, user data) | high |
| service availability | The embedding application continues to decode inputs in bounded time and memory | medium |
| decoded output integrity | PCM frames and metadata (loop points, channel count, sample rate) faithfully reflect the input stream | low |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| WAV decoder | `drwav_init_memory_with_metadata` and siblings; parses RIFF/WAVE container including metadata chunks (`smpl`, `cue`, `LIST`, `bext`, `inst`, `acid`) and PCM data. Metadata chunk handlers each read structured records with attacker-controlled count/size fields and allocate accordingly. | untrusted file bytes → process memory | host process integrity, adjacent process memory, service availability, decoded output integrity |
| FLAC decoder | `drflac_open_memory_and_read_pcm_frames_s16` and siblings; parses STREAMINFO, metadata blocks (PICTURE, VORBIS_COMMENT, SEEKTABLE, CUESHEET), and audio frames. STREAMINFO-derived values (`totalPCMFrameCount`, `maxBlockSizeInPCMFrames`, `channels`, `bitsPerSample`) size all downstream allocations and loop bounds. | untrusted file bytes → process memory | host process integrity, adjacent process memory, service availability, decoded output integrity |
| build pipeline | Single-header library vendored by copy from `github.com/mackron/dr_libs`; no package manager, signature, or lockfile in the typical embedder. The Dockerfile here pins a commit hash; downstream consumers generally do not. | upstream repo → consumer build | host process integrity, decoded output integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Memory corruption leading to remote code execution via untrusted audio file parsing | remote_unauth | WAV decoder, FLAC decoder | host process integrity | critical | likely | unmitigated | none | CVE-2026-29022, CVE-2025-14369 |
| T2 | Supply-chain compromise of vendored single-header dependency via malicious upstream commit or typosquatted fork copied into consumer build | supply_chain | build pipeline | host process integrity | critical | rare | partially_mitigated | pinned commit | |
| T3 | Information disclosure via out-of-bounds heap read returning adjacent memory in decoded frames or metadata fields | remote_unauth | WAV decoder, FLAC decoder | adjacent process memory | high | possible | unmitigated | none | |
| T4 | Denial of service via resource exhaustion; attacker-controlled size fields trigger unbounded allocation or O(n^2) decode loops | remote_unauth | FLAC decoder, WAV decoder | service availability | medium | likely | unmitigated | none | CVE-2025-14369 |
| T5 | Tampering with decoded audio or metadata (loop counts, channel count, sample rate) causing downstream logic errors in the embedder | remote_unauth | WAV decoder, FLAC decoder | decoded output integrity | low | possible | unmitigated | none | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing of audio source identity | Decoder has no identity or authentication semantics; provenance is the embedder's concern |
| Repudiation of decode actions | Library has no multi-user actions or audit semantics; nothing to repudiate |
| Elevation of privilege within the library | No internal privilege boundary; elevation is subsumed by T1 (RCE at embedder privilege) |

## 6. Open questions

- Does the embedder run the decoder in-process at full privilege, or in a sandboxed subprocess (seccomp, separate UID, WASM)?
- Who supplies input files in practice: end users / the network, or only trusted bundled assets?
- Is there an upstream size cap on input files or chunk counts before bytes reach `drwav_init_*` / `drflac_open_*`?
- Is DoS (T4) acceptable for the deployment, e.g. desktop app where crash-and-restart is tolerable vs a shared transcoding service?
- Do consumers pin a reviewed commit hash when vendoring, or pull `HEAD`?

## 7. Provenance

- mode: bootstrap
- date: 2026-04-19
- target: targets/drlibs @ fb1b2dfc585c
- inputs: /tmp/drlibs_cves.txt; targets/drlibs/README.md
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Run the decoder in a sandboxed subprocess (seccomp + rlimit, or WASM) and marshal PCM out over a pipe | T1,T3,T4 | yes | L |
| Hard-cap every attacker-supplied count/size field and use a checked-multiply helper before any allocation or loop bound | T1,T3,T4 | partial | M |
| Pin the vendored header to a reviewed commit hash and verify a checksum at build time | T2 | partial | S |
| Range-validate parsed metadata (channel count, sample rate, loop counts) before handing to embedder logic | T5 | partial | S |
