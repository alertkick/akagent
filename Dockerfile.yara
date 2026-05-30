# Builds a statically-linked `yara` CLI. Built per-platform via buildx in the
# dedicated akagent-yara Jenkins job (Jenkinsfile.yara); the `export` target
# emits just the binary so the job can pull it out with
# `--output type=local`. The agent bundles the result at
# /usr/lib/alertkick-agent/bin/yara.
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        automake libtool make gcc pkg-config libssl-dev libjansson-dev \
        libmagic-dev flex bison file curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG YARA_VERSION=4.5.2
WORKDIR /src
RUN curl -sfL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" | tar xz
WORKDIR /src/yara-${YARA_VERSION}

# Fully-static binary so it runs on any host regardless of libc/libssl version.
# If static linking against system libs fails on a given base image, drop the
# heavy optional modules: re-run configure with `--without-crypto --without-magic`
# for a leaner static build (loses the hash/magic modules).
RUN ./bootstrap.sh \
    && ./configure --disable-shared --enable-static --with-crypto LDFLAGS="-static" \
    && make -j"$(nproc)" \
    && strip yara

# Export stage: only the binary, so `buildx --output type=local` writes ./yara.
FROM scratch AS export
COPY --from=build /src/yara-*/yara /yara
