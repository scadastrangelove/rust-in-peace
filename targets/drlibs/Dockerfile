FROM gcc:14

WORKDIR /work

RUN apt-get update && \
    apt-get install -y --no-install-recommends python3 xxd file gdb && \
    rm -rf /var/lib/apt/lists/*

# Fetch the target source at build time, pinned to the vulnerable commit
# (parent of the dr_flac fix; both parsers vulnerable). This keeps vulnerable
# third-party source out of the repo — it exists only inside the container.
# Single-header libraries, no build step.
ARG COMMIT=fb1b2dfc585c
ADD https://raw.githubusercontent.com/mackron/dr_libs/${COMMIT}/dr_wav.h  /work/dr_wav.h
ADD https://raw.githubusercontent.com/mackron/dr_libs/${COMMIT}/dr_flac.h /work/dr_flac.h

COPY entry.c /work/entry.c

# -O1: ASAN-recommended. -fno-omit-frame-pointer: readable stacks.
RUN gcc -O1 -g -fsanitize=address -fno-omit-frame-pointer \
        -o /work/entry /work/entry.c -lm

CMD ["/bin/bash"]
