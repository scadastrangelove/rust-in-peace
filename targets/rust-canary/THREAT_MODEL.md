# Threat model — rustcanary

Format matching the `/threat-model` output shape, so `/vuln-scan` can consume it.

## 1. Overview

`rustcanary` is a binary "record table" parser. A caller hands `parse(bytes)`
untrusted bytes and then calls `Table` methods on the result. Pure byte parser:
no wire protocol, no auth, no persistence.

## 2. Assets

- Process memory of any host embedding the parser (OOB read → info disclosure).
- Availability of that process (panic / hang → DoS).

## 3. Entry points & trust boundaries

| Entry point | Input | Trust |
|-------------|-------|-------|
| `parse(bytes)` | arbitrary `&[u8]` | **untrusted** (attacker-controlled) |
| `Table::sum_record(i)` | record fields (`data_off`, `data_len`) | **untrusted** — from the parsed bytes |
| `Table::walk_chain(start)` | record `next` links | **untrusted** |
| `Table::first_byte_checked(i)` | record fields | untrusted, but bounded internally |

The integrity checksum verified in `parse` is **not** a trust boundary for
bounds: it proves the bytes are intact, not that internal offsets/counts are
in-range. Everything after the checksum is attacker-controlled.

## 4. Threats

| # | Threat | Vector | Impact |
|---|--------|--------|--------|
| T1 | OOB read | `data_off`/`data_len` past the data blob, read via unchecked `unsafe` pointer in `sum_record` | memory disclosure / crash |
| T2 | Panic DoS | untrusted `n_recs` makes the records slice exceed the buffer in `parse` | abort (availability) |
| T3 | Hang DoS | cyclic `next` in `walk_chain`, no cycle/step bound | unbounded loop (availability) |

## 5. Out of scope

- Panics reachable only from the driver's own CLI arg handling.
- OOM from an honestly-huge input (the harness excludes plain allocation-size).
- The `first_byte_checked` path — its unsafe read is bounded by a preceding
  validation and is NOT a vulnerability (included as a triage false-positive).
