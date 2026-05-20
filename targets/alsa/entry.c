// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
// entry: ./entry <topology-file>
// ALSA topology supports two input forms: a text config (loaded via the
// ALSA config parser) and a compiled binary blob (decoded via the ASoC
// topology decoder). Try both parse paths — each fails fast on the wrong
// format.

#include <stdio.h>
#include <stdlib.h>

#include <alsa/asoundlib.h>
#include <alsa/topology.h>

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); return 2; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    snd_tplg_t *tplg;

    tplg = snd_tplg_new();
    if (tplg) {
        snd_tplg_decode(tplg, buf, (size_t)sz, 0);
        snd_tplg_free(tplg);
    }

    tplg = snd_tplg_new();
    if (tplg) {
        snd_tplg_load(tplg, buf, (size_t)sz);
        snd_tplg_free(tplg);
    }

    free(buf);
    return 0;
}
