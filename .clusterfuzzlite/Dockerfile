# Build image for ClusterFuzzLite / OSS-Fuzz. Same contract as an upstream OSS-Fuzz project, with
# the one documented difference: ClusterFuzzLite COPYs the checkout in, where OSS-Fuzz git-clones it.
# PINNED by digest, like every `uses:` in .github/workflows is pinned by SHA. Untagged, this
# resolved to whatever :latest happened to be that morning, so the environment the fuzzers are
# built in could change with no commit here — and a fuzz build that changes under you is a green
# tick that means something different each week. Bump deliberately:
#   curl -sSL https://gcr.io/v2/oss-fuzz-base/base-builder-python/manifests/latest \
#     -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' -D - -o /dev/null \
#     | grep -i docker-content-digest
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:6b2b3a7e4a2da50de47f94925cffbe34747e1aae4f33d7f07ba6c681dd648b23
# No USER line, deliberately: root is the base-builder contract. ClusterFuzzLite's build step runs
# `cd / && rm -rf /src/linuxgsm-panel/* && cp -r <checkout> /src && cd - && compile` in this image
# (oss-fuzz infra/cifuzz/continuous_integration.py), and compile writes $OUT and $WORK. As any
# other user the rm and the cp fail on the root-owned /src. The image only compiles, on an
# ephemeral runner: nothing pushes or deploys it, and the fuzz targets run inside the run_fuzzers
# action's own image, not this one. Sonar's docker:S6471 on the FROM line wants a review in
# SonarCloud rather than a NOSONAR: a Dockerfile allows no trailing comment for one to sit in.

# The panel's runtime dependencies. They have to be present at BUILD time, not just at run time:
# PyInstaller bundles what it can import while compiling each fuzzer, so a missing dependency here
# becomes a fuzzer that dies on startup instead of a build that fails loudly.
# Copied on its own first so this layer caches across source-only changes. It is a hashed lockfile
# (see requirements.in): every file pip fetches must match a hash in it, and all of them are wheels.
COPY requirements.txt $SRC/requirements.txt
RUN pip3 install --no-cache-dir --require-hashes --only-binary :all: -r "$SRC/requirements.txt"

# The whole context, which is the repository root: /.dockerignore keeps .git, .claude (worktree
# checkouts), the venvs and every data/, key and database file out of this layer.
COPY . $SRC/linuxgsm-panel
WORKDIR $SRC/linuxgsm-panel
COPY .clusterfuzzlite/build.sh $SRC/
