# Bundling the static `yara` binary

The agent shells out to `yara` for malware scanning (`agent/yarascan`). To give
every host a consistent, version-matched binary — so server-compiled rules load
correctly — we bundle a statically-linked `yara` in the agent package per arch,
rather than depending on the host having one installed.

The agent prefers, in order:
1. `YARA_BIN` (explicit override)
2. the bundled binary at `/usr/lib/alertkick-agent/bin/yara`
3. `yara` from `PATH`

So bundling is purely additive — if the bundled binary is absent, the agent
falls back to a system `yara`, and if neither exists YARA scanning is simply
dormant.

## Producing the binaries

`build-static-yara.sh` builds a static `yara` for the current arch into
`packaging/linux/yara/yara-<arch>`. Run it once per target arch in CI (inside
`Dockerfile.build`) **before** `goreleaser release`. It needs yara's build deps
(see the script header). Cross-arch builds should run on a native runner per
arch, or via `docker buildx` with the matching platform.

Result:
```
packaging/linux/yara/yara-amd64
packaging/linux/yara/yara-arm64
```
These are build artifacts — keep them out of git (add to `.gitignore`).

## goreleaser wiring (enable after the binaries are produced)

Add to **each** `nfpms` entry (deb and rpm) under `contents:` in
`.goreleaser.yml`:

```yaml
      - src: packaging/linux/yara/yara-{{ .Arch }}
        dst: /usr/lib/alertkick-agent/bin/yara
        file_info:
          mode: 0755
```

And to the linux `archives` entry, add under a `files:` list the same templated
source. `{{ .Arch }}` resolves to `amd64` / `arm64`, matching the filenames the
build script writes.

> Not wired into `.goreleaser.yml` yet on purpose: referencing the binaries
> before CI produces them would fail every release. Enable the snippet above in
> the same change that adds the `build-static-yara.sh` step to the build
> pipeline.

## Dockerfile.build step

Before the goreleaser invocation, build the static yara for the image's arch:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
      automake libtool make gcc pkg-config libssl-dev libjansson-dev \
      libmagic-dev flex bison file \
    && rm -rf /var/lib/apt/lists/*
# ... then in the build entrypoint, run packaging/linux/yara/build-static-yara.sh
```

## Rules

The binary is bundled; the **rules** are delivered separately by the rules-sync
loop (`agent/yarasync`) pulling `GET /agent/yara-rules/current`. The base pack
ships only permissive/public-domain rules; customers add their own (and own
their licensing) via the `/yara-rules` API.
