// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
// entry: ./entry <audio-file>
// Sniff magic bytes and dispatch. WAV path enables metadata parsing (smpl,
// cue, LIST, bext, ...) — it's a strict superset of the plain init and any
// consumer that wants loop points or broadcast metadata uses it. FLAC path
// uses the read-all convenience function, the typical "give me the decoded
// audio" call pattern.

#define DR_WAV_IMPLEMENTATION
#include "dr_wav.h"
#define DR_FLAC_IMPLEMENTATION
#include "dr_flac.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void do_wav(const unsigned char *buf, size_t len) {
    drwav wav;
    if (!drwav_init_memory_with_metadata(&wav, buf, len, 0, NULL)) return;
    drwav_int16 *frames = malloc(4096 * wav.channels * sizeof(drwav_int16));
    if (frames) {
        while (drwav_read_pcm_frames_s16(&wav, 4096, frames) > 0) { }
        free(frames);
    }
    drwav_uninit(&wav);
}

static void do_flac(const unsigned char *buf, size_t len) {
    unsigned int channels, rate;
    drflac_uint64 total;
    drflac_int16 *pcm = drflac_open_memory_and_read_pcm_frames_s16(
        buf, len, &channels, &rate, &total, NULL);
    if (pcm) drflac_free(pcm, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 2; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); return 2; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    if (sz >= 4 && memcmp(buf, "RIFF", 4) == 0)      do_wav(buf, (size_t)sz);
    else if (sz >= 4 && memcmp(buf, "fLaC", 4) == 0) do_flac(buf, (size_t)sz);
    else {
        do_wav(buf, (size_t)sz);
        do_flac(buf, (size_t)sz);
    }

    free(buf);
    return 0;
}
