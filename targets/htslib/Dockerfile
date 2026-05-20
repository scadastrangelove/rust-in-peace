FROM gcc:14

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 xxd file gdb \
        autoconf automake libtool pkg-config \
        zlib1g-dev libbz2-dev liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

# Pinned to 1.23 — the release tarball ships the configure script and the
# htscodecs submodule already, so no autoreconf / submodule init needed.
ARG VERSION=1.23
ADD https://github.com/samtools/htslib/releases/download/${VERSION}/htslib-${VERSION}.tar.bz2 /tmp/src.tar.bz2
RUN mkdir -p /work/src && \
    tar xjf /tmp/src.tar.bz2 -C /work/src --strip-components=1 && \
    rm /tmp/src.tar.bz2

# ASAN-instrumented static build. Disable network (curl/S3/GCS) and
# plugins — we're testing file parsers only. Keep bz2+lzma for CRAM
# codec support.
RUN cd /work/src && \
    ./configure \
        --disable-libcurl --disable-gcs --disable-s3 --disable-plugins \
        --without-libdeflate \
        CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address" && \
    make -j"$(nproc)" libhts.a

COPY entry.c /work/entry.c
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -I/work/src \
        -o /work/entry /work/entry.c \
        /work/src/libhts.a \
        -lz -lbz2 -llzma -lm -lpthread

CMD ["/bin/bash"]
