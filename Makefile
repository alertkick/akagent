# Change these variables as necessary.
MAIN_PACKAGE_PATH := ./cmd
BINARY_NAME := alertkick-agent
TARGET=build/alertkick-agent

all: $(TARGET)

$(TARGET):
	cmake -H. -Bbuild
	cmake --build build
	build/alertkick-agent -v

# ==================================================================================== #
# HELPERS
# ==================================================================================== #

## help: print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'

.PHONY: confirm
confirm:
	@echo -n 'Are you sure? [y/N] ' && read ans && [ $${ans:-N} = y ]

.PHONY: no-dirty
no-dirty:
	git diff --exit-code


# ==================================================================================== #
# QUALITY CONTROL
# ==================================================================================== #

## tidy: format code and tidy modfile
.PHONY: tidy
tidy:
	go fmt ./...
	go mod tidy -v

## audit: run quality control checks
.PHONY: audit
audit:
	go mod verify
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest -checks=all,-ST1000,-U1000 ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	go test -race -buildvcs -vet=off ./...


# ==================================================================================== #
# DEVELOPMENT
# ==================================================================================== #

## test: run all tests
.PHONY: test
test:
	go test -v -race -buildvcs ./...

## test/cover: run all tests and display coverage
.PHONY: test/cover
test/cover:
	go test -v -race -buildvcs -coverprofile=/tmp/coverage.out ./...
	go tool cover -html=/tmp/coverage.out

## bpf/generate: generate eBPF Go bindings from BPF C code
.PHONY: bpf/generate
bpf/generate:
	cd ebpf/bpfgen && go generate ./...

## build: build the application
.PHONY: build
build: bpf/generate
	$(eval VERSION := $(shell ./version.sh))
	go build -ldflags="-X main.Version=$(VERSION) -X apagent/ebpf.agentVersion=$(VERSION)" -o=build/${BINARY_NAME} ${MAIN_PACKAGE_PATH}

## run: run the  application
.PHONY: run
run: build
	build/${BINARY_NAME}

## run/live: run the application with reloading on file changes
.PHONY: run/live
run/live:
	go run github.com/cosmtrek/air@v1.43.0 \
		--build.cmd "make build" --build.bin "build/${BINARY_NAME}" --build.delay "100" \
		--build.exclude_dir "" \
		--build.include_ext "go, tpl, tmpl, html, css, scss, js, ts, sql, jpeg, jpg, gif, png, bmp, svg, webp, ico" \
		--misc.clean_on_exit "true"


# ==================================================================================== #
# OPERATIONS
# ==================================================================================== #

## push: push changes to the remote Git repository
.PHONY: push
push: tidy audit no-dirty
	git push

## production/deploy: deploy the application to production
.PHONY: production/deploy
production/deploy: confirm tidy audit no-dirty
	GOOS=linux GOARCH=amd64 go build -ldflags='-s' -o=/tmp/bin/linux_amd64/${BINARY_NAME} ${MAIN_PACKAGE_PATH}
	upx -5 /tmp/bin/linux_amd64/${BINARY_NAME}
	# Include additional deployment steps here...


## licenses: collect third-party license files into a directory
.PHONY: licenses
licenses:
	go install github.com/google/go-licenses@latest
	go-licenses save ./cmd/... --ignore apagent --save_path=./third_party_licenses --force

## licenses/check: verify no restricted (GPL) licenses are used
.PHONY: licenses/check
licenses/check:
	go install github.com/google/go-licenses@latest
	go-licenses check ./cmd/... --ignore apagent --disallowed_types=restricted

## licenses/report: generate a CSV report of all dependency licenses
.PHONY: licenses/report
licenses/report:
	go install github.com/google/go-licenses@latest
	go-licenses report ./cmd/... --ignore apagent

## release/build: build all platform packages with goreleaser (no publish)
.PHONY: release/build
release/build: bpf/generate
	goreleaser release --clean --skip=publish

## release/snapshot: build snapshot packages (no version tag needed)
.PHONY: release/snapshot
release/snapshot: bpf/generate
	goreleaser release --clean --snapshot

.PHONY: clean
clean:
	rm -rf build dist

## package: build all packages using Docker + GoReleaser (same as Jenkins CI)
.PHONY: package
package: clean
	docker build -f Dockerfile.build -t apagent-build .
	docker rm -f apagent-builder 2>/dev/null || true
	docker create --name apagent-builder -w /build apagent-build sh -c '\
		set -e && \
		echo "=== Downloading modules ===" && \
		go mod download && \
		echo "=== License Check ===" && \
		go-licenses check ./cmd/... --ignore apagent --disallowed_types=restricted && \
		echo "=== License Collect ===" && \
		go-licenses save ./cmd/... --ignore apagent --save_path=./third_party_licenses --force && \
		echo "=== Build & Package ===" && \
		goreleaser release --clean --skip=publish && \
		echo "=== Generate Per-Package Checksums ===" && \
		cd dist && \
		for f in *.deb *.rpm *.tar.gz *.zip; do \
			[ -f "$$f" ] || continue; \
			sha256sum "$$f" > "$${f}.checksum"; \
			echo "  $${f}.checksum"; \
		done && \
		cd .. && \
		echo "=== Dist Contents ===" && \
		ls -lh dist/'
	docker cp $$(pwd)/. apagent-builder:/build/
	docker start -a apagent-builder
	docker cp apagent-builder:/build/dist/. $$(pwd)/dist/
	docker rm apagent-builder

## package/upload: upload packages to download server
.PHONY: package/upload
package/upload:
	scp dist/*.deb dist/*.rpm dist/*.tar.gz dist/*.zip dist/*.checksum \
		root@endpoint1.ssidhu.io:/data/containers/ak-wildcard-api/download-packages/