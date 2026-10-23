FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d
# Frozen Debian repository snapshot; no package installation occurs during runs.
RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260225T000000Z bookworm main' > /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends clang-14 python3-clang-14 make perl libc6-dev && \
    mkdir -p /opt/pqscan && dpkg-query -W > /opt/pqscan/toolchain-packages.txt && \
    rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/local/bin:/usr/bin:/bin LANG=C.UTF-8
LABEL org.pqscan.library.recipe="openssl-evp-portable-v1"
USER 65534:65534
WORKDIR /work
