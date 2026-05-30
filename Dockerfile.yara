# Builds a statically-linked `yara` CLI. Built per-platform via buildx in the
# dedicated akagent-yara Jenkins job (Jenkinsfile.yara); the `export` target
# emits just the binary so the job can pull it out with
# `--output type=local`. The agent bundles the result at
# /usr/lib/alertkick-agent/bin/yara.
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        automake autoconf libtool make gcc pkg-config \
        libssl-dev libjansson-dev zlib1g-dev \
        flex bison file curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ARG YARA_VERSION=4.5.2
WORKDIR /src
RUN curl -sfL "https://github.com/VirusTotal/yara/archive/refs/tags/v${YARA_VERSION}.tar.gz" | tar xz
WORKDIR /src/yara-${YARA_VERSION}

# Static binary so it runs on any host regardless of libc/libssl version.
# IMPORTANT: do NOT pass LDFLAGS=-static to ./configure — it breaks configure's
# pthread probe ("pthread API support is required"). Configure normally, then
# static-link only at the final make step with libtool's -all-static. The magic
# module is left off (not --enable-magic'd) to avoid a libmagic static dep; the
# crypto module stays for the hash/pe checks malware rules use.
RUN ./bootstrap.sh \
    && ./configure --disable-shared --enable-static --with-crypto \
    && make -j"$(nproc)" LDFLAGS="-all-static" \
    && strip yara

# Export stage: only the binary, so `buildx --output type=local` writes ./yara.
FROM scratch AS export
COPY --from=build /src/yara-*/yara /yara
