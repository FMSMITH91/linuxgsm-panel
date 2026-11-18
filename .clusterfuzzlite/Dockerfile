# Build image for ClusterFuzzLite / OSS-Fuzz. Same contract as an upstream OSS-Fuzz project, with
# the one documented difference: ClusterFuzzLite COPYs the checkout in, where OSS-Fuzz git-clones it.
# PINNED by digest, like every `uses:` in .github/workflows is pinned by SHA. Untagged, this
# resolved to whatever the tag named that morning, so the environment the fuzzers are built in
# could change with no commit here, and a fuzz build that changes under you is a green tick that
# means something different each week. Docker pulls by the digest alone; the tag beside it names
# what the digest was read from, so Renovate's dockerfile manager (.github/renovate.json) can look
# the tag up and propose its new digest as a reviewed commit. The tag is ubuntu-24-04, the base that
# .clusterfuzzlite/project.yaml's base_os_version selects: `latest` is still the legacy Ubuntu 20.04
# (OSS-Fuzz docs/getting-started/continuous_integration.md, "Ubuntu 24.04 Support"), past its
# standard support. The images that build and run this one are this repository's copies of the
# ClusterFuzzLite actions, pinned the same way (.github/actions/cflite-*). Scorecard's action image
# cannot be: publish_results is accepted only from a job whose steps are all on its approved list
# (ossf/scorecard-action README, "Workflow Restrictions"), so scorecard.yml checks that the tag
# still names the digest it records, before the run and in the run's own pull. To check a Renovate
# proposal, or bump this one by hand:
#   curl -sSL https://gcr.io/v2/oss-fuzz-base/base-builder-python/manifests/ubuntu-24-04 \
#     -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' -D - -o /dev/null \
#     | grep -i docker-content-digest
# Keep FROM on line 21: SonarCloud tracks its Accepted docker:S6471 by rule, line and message.
FROM gcr.io/oss-fuzz-base/base-builder-python:ubuntu-24-04@sha256:56c7b79a492890e6ca979816a09f25ce6393802a3917bfba0cfd76f1c9ded1b7
# No USER line, deliberately: root is the base-builder contract. ClusterFuzzLite's build step runs
# `cd / && rm -rf /src/linuxgsm-panel/* && cp -r <checkout> /src && cd - && compile` in this image
# (oss-fuzz infra/cifuzz/continuous_integration.py), with no --user (infra/cifuzz/docker.py). As
# any other user the rm fails on the root-owned tree the COPY lines below make, and compile itself
# stops at its first step: compile_libfuzzer copies the engine to /usr/lib/libFuzzingEngine.a
# ("cp: cannot create regular file '/usr/lib/libFuzzingEngine.a': Permission denied" as uid 1001).
# $OUT, which compile then fills, is made by the build action's own root container. The image
# only compiles, on an ephemeral runner: nothing pushes or deploys it, and the fuzz targets run
# inside the run_fuzzers action's own image, not this one. Sonar's docker:S6471 on the FROM line
# wants a review in SonarCloud rather than a NOSONAR: a Dockerfile allows no trailing comment for
# one to sit in.

# The panel's runtime dependencies. They have to be present at BUILD time, not just at run time:
# PyInstaller bundles what it can import while compiling each fuzzer, so a missing dependency here
# becomes a fuzzer that dies on startup instead of a build that fails loudly.
# Copied on its own first so this layer caches across source-only changes. It is a hashed lockfile
# (see requirements.in): every file pip fetches must match a hash in it, and all of them are wheels.
# --no-deps, as install.sh installs it: the file is the whole closure apart from the packages its
# header leaves out, which other metadata still declares and the panel does not use (requirements.in).
COPY panel/install/requirements.txt $SRC/requirements.txt
RUN pip3 install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r "$SRC/requirements.txt"

# What the fuzz build reads, not the whole context. The harnesses import panel.* and nothing else
# (a part06 gate holds them to that), and build.sh reads tests/fuzz/ and its seed corpora; the
# rest of the repository (.git, .claude's worktree checkouts, data/, the venvs) stays out of the
# layer by construction. /.dockerignore still guards the context. On CI, ClusterFuzzLite swaps
# $SRC/linuxgsm-panel for a copy of the checkout before it compiles, so this is what a local
# `helper.py build_image` gets.
COPY panel $SRC/linuxgsm-panel/panel
COPY tests/fuzz $SRC/linuxgsm-panel/tests/fuzz
WORKDIR $SRC/linuxgsm-panel
COPY .clusterfuzzlite/build.sh $SRC/
