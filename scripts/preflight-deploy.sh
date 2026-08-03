#!/usr/bin/env bash
# preflight-deploy.sh — the DEPLOY-LAYER gate (LESSONS.md L59).
#
# Runs BEFORE any expensive containerized build/scan and settles, in seconds, the environment
# properties that otherwise surface only at the most expensive possible moment — an hour into a
# build, at layer export. Every failure prints a specific, actionable remediation and exits
# non-zero so the caller aborts instead of paying for a run the box cannot complete.
#
#   preflight-deploy.sh <image> [out-dir-to-writetest]
#
# Exit 0  → environment can run a containerized scan (egress may be WARN-only; see below).
# Exit !0 → a NAMED trap; do not proceed. The message says which and how to fix it.
#
# The traps this catches were all hit by hand on a hardened box (userns-remap +
# containerd-snapshotter + iptables:false) during the SAST bring-up; L59 is the write-up.
set -u -o pipefail

IMAGE=${1:?usage: preflight-deploy.sh <image> [out-dir]}
OUT_DIR=${2:-}
DOCKER=${DOCKER:-docker}

fail() { # <tag> <what> <remediation>
  echo "PREFLIGHT FAIL [$1]: $2" >&2
  echo "  remediation: $3" >&2
  exit 1
}

# 1) IMAGE PRESENT — the "image-is-gone" trap. A stale VERSIONS.txt or a prior run does NOT mean the
#    image still exists in this daemon's store.
$DOCKER image inspect "$IMAGE" >/dev/null 2>&1 || fail image-missing \
  "scan image '$IMAGE' is not present in this daemon" \
  "build it (docker/sast/build.sh) or transport one ('docker save … | ssh box docker load')"

# 2) EXPORT CANARY — the userns-remap + containerd-snapshotter "root-ownership" trap. Can this daemon
#    COMMIT a freshly-built layer that contains a root-owned file at all? Costs ~a few seconds and is
#    the single check that would have saved a 60-minute build whose ONLY failure was `failed to export
#    layer: host ID 0 cannot be mapped` at the very end.
W=$(mktemp -d)
printf 'FROM busybox:latest\nRUN touch /root/.rip-probe && chown 0:0 /root/.rip-probe\n' > "$W/Dockerfile"
if ! CO=$("$DOCKER" build -q -t rip-preflight-export:tmp "$W" 2>&1); then
  rm -rf "$W"
  if echo "$CO" | grep -qiE "cannot be mapped|failed to export layer"; then
    fail export-trap \
      "daemon cannot export a layer with root-owned files (userns-remap + containerd-snapshotter)" \
      "build the image where the overlay2 store is used (containerd-snapshotter off) or userns-remap is not set, then 'docker save … | ssh box docker load' the finished image; do NOT run the full build here"
  fi
  fail build-broken "daemon cannot build a trivial busybox image: $(echo "$CO" | tail -1)" \
    "inspect 'docker info' and the daemon log"
fi
"$DOCKER" rmi rip-preflight-export:tmp >/dev/null 2>&1 || true
rm -rf "$W"

# 3) EGRESS CANARY — the iptables:false / no-NAT / DNS-via-unreachable-stub trap. Only the FETCH phase
#    needs egress (ANALYZE runs --network none), so this is a WARN, not a hard fail: a pre-populated
#    /cargo makes egress unnecessary. But naming it up front turns a mid-build "Temporary failure
#    resolving deb.debian.org" into a one-line fix.
if "$DOCKER" run --rm "$IMAGE" sh -lc \
     'getent hosts deb.debian.org >/dev/null 2>&1 && curl -fsS -m 12 -4 -o /dev/null http://deb.debian.org/ 2>/dev/null' \
     >/dev/null 2>&1; then
  EGRESS=ok
else
  EGRESS=warn
  echo "PREFLIGHT WARN [egress]: containers have no outbound network (iptables=false / no NAT / DNS stub unreachable from netns)." >&2
  echo "  FETCH needs egress. Add an OUTBOUND-ONLY NAT for the docker bridge subnet (no DNAT, no inbound):" >&2
  echo "    iptables -t nat -A POSTROUTING -s <docker-subnet> -o <wan-if> -j MASQUERADE" >&2
  echo "  (If the box has no IPv6 route, prefer IPv4: echo 'precedence ::ffff:0:0/96 100' >> /etc/gai.conf in the image.)" >&2
  echo "  ANALYZE runs --network none and is unaffected; a pre-populated /cargo skips FETCH entirely." >&2
fi

# 4) RESULT WRITE-BACK — the root-owned-litter trap (L28-adjacent). If the scan container writes its
#    output as root, the box's own operator cannot delete their scratch dir. Verify the out-dir is
#    owner-writable-and-deletable through a --user-mapped run.
if [ -n "$OUT_DIR" ]; then
  mkdir -p "$OUT_DIR" 2>/dev/null || true
  "$DOCKER" run --rm --user "$(id -u):$(id -g)" -v "$OUT_DIR:/o" "$IMAGE" \
    sh -lc 'touch /o/.rip-writeprobe' >/dev/null 2>&1 || true
  if [ -f "$OUT_DIR/.rip-writeprobe" ] && rm -f "$OUT_DIR/.rip-writeprobe" 2>/dev/null; then
    :
  else
    fail writeback \
      "container output in '$OUT_DIR' is not owner-deletable (missing --user, or userns id-shift leaves root-owned files)" \
      "run the scan container with --user \$(id -u):\$(id -g) (see the FETCH note in docker/sast/sast-scan.sh)"
  fi
fi

echo "PREFLIGHT OK: image present · export works · write-back clean · egress=${EGRESS}"
exit 0
