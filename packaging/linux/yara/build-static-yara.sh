#!/usr/bin/env bash
# Build a statically-linked `yara` CLI for the current architecture and place it
# at packaging/linux/yara/yara-<arch> so goreleaser can bundle it into the agent
# package. Run this in CI (inside Dockerfile.build) for each target arch BEFORE
# `goreleaser release`. See README.md in this directory for the goreleaser wiring.
#
# Build deps (Debian/Ubuntu build image):
#   apt-get install -y build-essential automake libtool make pkg-config \
#       libssl-dev libjansson-dev libmagic-dev flex bison
# For a fully static binary, the static variants of those libs must be present
# (libssl, libjansson, libmagic), or build them static first.
set -euo pipefail

YARA_VERSION="${YARA_VERSION:-4.5.2}"
ARCH="$(go env GOARCH 2>/dev/null || dpkg --print-architecture)"
OUT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "Building static yara ${YARA_VERSION} for arch=${ARCH}"
cd "$WORK"
curl -sfL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" | tar xz
cd "yara-${YARA_VERSION}"

./bootstrap.sh
# --disable-shared + static LDFLAGS produce a self-contained binary. Drop the
# optional modules that pull heavy deps if a smaller/portable build is wanted.
./configure --disable-shared --enable-static \
    --with-crypto \
    LDFLAGS="-static"
make -j"$(nproc)"

install -D -m 0755 "yara" "${OUT_DIR}/yara-${ARCH}"
echo "Wrote ${OUT_DIR}/yara-${ARCH}"
file "${OUT_DIR}/yara-${ARCH}" || true
