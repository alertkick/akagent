#!/bin/sh
set -e

echo "=== Downloading modules ==="
go mod download

echo "=== License Check ==="
go-licenses check ./cmd/... --ignore apagent --disallowed_types=restricted

echo "=== License Collect ==="
go-licenses save ./cmd/... --ignore apagent --save_path=./third_party_licenses --force

echo "=== Test ==="
CGO_ENABLED=1 go test -race ./...

echo "=== Build & Package ==="
if [ -d .git ]; then
    goreleaser release --clean --skip=publish
else
    goreleaser release --clean --skip=publish --snapshot
fi

echo "=== Generate Per-Package Checksums ==="
cd dist
for f in *.deb *.rpm *.tar.gz *.zip; do
    [ -f "$f" ] || continue
    sha256sum "$f" > "${f}.checksum"
    echo "  ${f}.checksum"
done
cd ..

echo "=== Dist Contents ==="
ls -lh dist/
