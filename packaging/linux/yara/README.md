# Bundling the static `yara` binary

The agent shells out to `yara` for malware scanning (`agent/yarascan`). We bundle
a statically-linked `yara` in the agent package per arch — so every host has a
consistent, version-matched binary and server-compiled rules load correctly —
rather than depending on the host having one installed.

The agent prefers, in order:
1. `YARA_BIN` (explicit override)
2. the bundled binary at `/usr/lib/alertkick-agent/bin/yara`
3. `yara` from `PATH`

So bundling is additive: if the bundled binary is absent the agent falls back to
a system `yara`, and if neither exists YARA scanning is simply dormant.

## How it's built and bundled (CI)

The binary is built **infrequently** (only on a YARA version bump), not on every
agent build:

1. **`akagent-yara` job** (`Jenkinsfile.yara`, manual/parameterized): builds a
   static `yara` for **amd64 and arm64** via buildx (`Dockerfile.yara`) and
   uploads them to S3:
   - `s3://alertkick-agent-packages/yara/<version>/yara-<arch>` (history)
   - `s3://alertkick-agent-packages/yara/latest/yara-<arch>` (the pointer the
     agent build reads)
2. **Main `akagent` build** (`Jenkinsfile`, every build): the *Fetch YARA
   binaries* stage downloads `yara/latest/yara-<arch>` into
   `packaging/linux/yara/`, and goreleaser bundles them via the `nfpms`/`archives`
   `contents` entries → `/usr/lib/alertkick-agent/bin/yara`.

So: run the `akagent-yara` job once (and again whenever bumping `YARA_VERSION`);
normal agent builds just pull the prebuilt binaries.

The `yara-amd64` / `yara-arm64` files are build artifacts — gitignored, never
committed.

## Local one-off build

`build-static-yara.sh` builds a static `yara` for the current arch into
`packaging/linux/yara/yara-<arch>` (handy for testing the bundle locally without
the CI job). Needs yara's build deps; see the script header.

## Rules

The binary is bundled; the **rules** are delivered separately by the rules-sync
loop (`agent/yarasync`) pulling `GET /agent/yara-rules/current`. The base pack
ships only permissive/public-domain rules; customers add their own (and own their
licensing) via the `/yara-rules` API and the Monitoring → YARA Rules UI.
