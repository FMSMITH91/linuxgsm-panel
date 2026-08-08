# Build image for ClusterFuzzLite / OSS-Fuzz. Same contract as an upstream OSS-Fuzz project, with
# the one documented difference: ClusterFuzzLite COPYs the checkout in, where OSS-Fuzz git-clones it.
FROM gcr.io/oss-fuzz-base/base-builder-python

# The panel's runtime dependencies. They have to be present at BUILD time, not just at run time:
# PyInstaller bundles what it can import while compiling each fuzzer, so a missing dependency here
# becomes a fuzzer that dies on startup instead of a build that fails loudly.
# Copied on its own first so this layer caches across source-only changes.
COPY requirements.txt $SRC/requirements.txt
RUN pip3 install --no-cache-dir -r $SRC/requirements.txt

COPY . $SRC/linuxgsm-panel
WORKDIR $SRC/linuxgsm-panel
COPY .clusterfuzzlite/build.sh $SRC/
