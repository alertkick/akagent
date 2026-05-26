# Changelog

All notable changes to the AlertKick agent are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Semantic Versioning](https://semver.org/).

## [v1.7.0] — first public release

This is the first version of the AlertKick agent published to a public
GitHub repository. The agent itself was already running in production;
this release marks the point at which its source becomes openly visible.

### Public scope

The agent captures and enriches eBPF security events. It carries the
public-knowledge exclusion sets needed to drop high-volume noise at
source (coreutils binaries, login subsystems, package managers,
container runtimes, etc.).

### Out of scope on purpose

Framework-specific detection IP — the matchers that decide whether a
given event is evidence of a SOX, PCI-DSS, HIPAA, or other compliance
control — lives at the endpoint, not in this agent. The agent emits
public tags only (`privilege`, `setuid`, `filesystem`, …); the endpoint
classifies events authoritatively over its own SOX/PCI/etc. lists.

### Distribution

Release artifacts (`.deb`, `.rpm`, `.tar.gz`, `.zip`, per-package
`.checksum` files) are published to:

- **GitHub Releases** — public, direct downloads from this repository.
- **AlertKick package CDN** — used by hosts installed via the AlertKick
  console install script.
