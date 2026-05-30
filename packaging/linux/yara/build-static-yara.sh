#!/usr/bin/env bash
# Build a statically-linked `yara` CLI for the current architecture and place it
# at packaging/linux/yara/yara-<arch> so goreleaser can bundle it into the agent
# package. Run this in CI (inside Dockerfile.build) for each target arch BEFORE
# `goreleaser release`. See README.md in this directory for the goreleaser wiring.
#
# Build deps (Debian/Ubuntu build image):
#   apt-get install -y build-essential automake autoconf libtool make pkg-config \
#       libssl-dev libjansson-dev zlib1g-dev flex bison file
# The -dev packages ship the static .a libs that -all-static needs.
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
# Do NOT pass LDFLAGS=-static to configure (breaks its pthread probe). Configure
# normally, then static-link at the make step with libtool's -all-static.
./configure --disable-shared --enable-static --with-crypto
make -j"$(nproc)" LDFLAGS="-all-static"

install -D -m 0755 "yara" "${OUT_DIR}/yara-${ARCH}"
echo "Wrote ${OUT_DIR}/yara-${ARCH}"
file "${OUT_DIR}/yara-${ARCH}" || true
