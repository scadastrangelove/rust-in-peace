# android-app pipeline target image: ships a SYNTHETIC decompiled-APK fixture
# (decoded AndroidManifest.xml + smali/) plus the reachability oracle. There is
# no NDK, no emulator, and no real APK — the canary validates that the android-app
# profile (find prompt + witness detector + capability gates + DISPOSITION gate)
# is wired correctly, the android analog of targets/rust-canary.
FROM python:3.12-slim
WORKDIR /work

# A real android target DECODES the APK and re-walks it with androguard (DEX +
# binary-XML manifest) and/or apktool (smali). androguard is installed here so
# the image mirrors a real target and a reviewer can re-decode; the canary's own
# oracle stays dependency-free (stdlib ElementTree + line grep over the fixture),
# so it runs even if this install is skipped.
RUN pip install --no-cache-dir androguard
# apktool (APK -> smali + decoded manifest) needs a JRE; a real target adds e.g.:
#   apt-get update && apt-get install -y --no-install-recommends default-jre-headless \
#     && curl -L https://.../apktool.jar -o /usr/local/bin/apktool.jar
#   apktool d app.apk -o /work/app

# decoded tree: AndroidManifest.xml + smali/  (Docker has no inline COPY comments)
COPY app /work/app
# example candidate paths (seed /poc for the re-attack sweep)
COPY candidates /work/candidates
# the reachability oracle (binary_path)
COPY reach /work/reach
COPY run_detectors.sh /work/run_detectors.sh
RUN chmod +x /work/reach /work/run_detectors.sh

# reach resolves the decoded tree via APP_ROOT (falls back to /work/app). The
# oracle: `reach <candidate>` -> a strength-1 WITNESS block (exit 1) or a
# `reject:` line (exit 0). run_detectors.sh drives it for the re-attack stage.
ENV APP_ROOT=/work/app
CMD ["/bin/bash"]
