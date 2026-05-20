// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
// Canary target: deliberately vulnerable, for fast pipeline iteration.
//
// Three "parsers" selected by the first byte of input. Each has one planted
// bug with a distinct ASAN signature — so a working find loop lands a crash
// in <10 turns, focus-area steering is testable (3 areas → 3 agents → 3
// different crashes), and dedup has 3 distinct (crash_type, top_frame) tuples.
//
// This is NOT production code. It exists so pipeline changes can be verified
// in minutes instead of hours against a real target.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ─── Parser A: heap-buffer-overflow ──────────────────────────────────────────
// Allocates a small fixed buffer, then copies an input-controlled length into
// it. ASAN: heap-buffer-overflow (WRITE).
__attribute__((noinline))
static void parse_alpha(const unsigned char *buf, size_t len) {
    if (len < 2) return;
    size_t claimed = buf[0];  // length field from input, 0-255
    unsigned char *out = malloc(8);
    if (!out) return;
    // Bug: trusts claimed length without bounding to allocation size.
    memcpy(out, buf + 1, claimed);
    // Use the buffer so the write isn't dead-code-eliminated.
    printf("alpha: first=%u\n", out[0]);
    free(out);
}

// ─── Parser B: stack-buffer-overflow ─────────────────────────────────────────
// Fixed stack buffer, copies input bytes without a bound check.
// ASAN: stack-buffer-overflow (WRITE).
__attribute__((noinline))
static void parse_bravo(const unsigned char *buf, size_t len) {
    char name[16];
    // Bug: no check that len fits in name[].
    memcpy(name, buf, len);
    name[sizeof(name) - 1] = '\0';
    printf("bravo: name=%.15s\n", name);
}

// ─── Parser C: heap-use-after-free ───────────────────────────────────────────
// Frees early on a sentinel value, then writes through the dangling pointer.
// ASAN: heap-use-after-free (WRITE).
struct record { int id; int value; };

__attribute__((noinline))
static void parse_charlie(const unsigned char *buf, size_t len) {
    if (len < 2) return;
    struct record *r = malloc(sizeof *r);
    if (!r) return;
    r->id = buf[0];
    if (r->id == 0xff) {
        // Bug: early-free path doesn't return; falls through to the write below.
        free(r);
    }
    r->value = buf[1];  // UAF when id == 0xff
    printf("charlie: id=%d value=%d\n", r->id, r->value);
    if (r->id != 0xff) free(r);
}

// ─── Dispatch ────────────────────────────────────────────────────────────────
int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    unsigned char buf[4096];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);

    if (n < 1) { fprintf(stderr, "empty input\n"); return 1; }

    switch (buf[0]) {
        case 'A': parse_alpha(buf + 1, n - 1);   break;
        case 'B': parse_bravo(buf + 1, n - 1);   break;
        case 'C': parse_charlie(buf + 1, n - 1); break;
        default:
            fprintf(stderr, "unknown format byte 0x%02x (want 'A', 'B', or 'C')\n", buf[0]);
            return 1;
    }
    return 0;
}
