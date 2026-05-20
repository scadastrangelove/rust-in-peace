// Copyright 2026 Anthropic PBC
// SPDX-License-Identifier: Apache-2.0
// entry: ./entry <file>
// htslib exposes two parsing surfaces exercised here: (1) the BGZF index
// (.gzi) loader — opens the input as a GZI index file into a fresh BGZF
// handle; (2) the SAM/BAM/CRAM reader — opens the input as an alignment
// file (format auto-detected by sam_open) and iterates records. Call both
// unconditionally; each fails fast on a wrong-format input.

#include <stdio.h>
#include <stdlib.h>

#include "htslib/bgzf.h"
#include "htslib/hts.h"
#include "htslib/sam.h"

static void do_gzi(const char *path) {
    BGZF *fp = bgzf_open(path, "r");
    if (!fp) return;
    bgzf_index_load(fp, path, NULL);
    bgzf_close(fp);
}

static void do_sam(const char *path) {
    samFile *sf = sam_open(path, "r");
    if (!sf) return;
    sam_hdr_t *hdr = sam_hdr_read(sf);
    if (hdr) {
        bam1_t *rec = bam_init1();
        if (rec) {
            while (sam_read1(sf, hdr, rec) >= 0) { }
            bam_destroy1(rec);
        }
        sam_hdr_destroy(hdr);
    }
    sam_close(sf);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    do_gzi(argv[1]);
    do_sam(argv[1]);
    return 0;
}
