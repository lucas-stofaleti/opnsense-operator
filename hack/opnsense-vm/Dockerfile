# QEMU toolbox for booting OPNsense nano images headlessly.
# Bundles qemu + expect so the bring-up works identically on a laptop and a CI runner.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        qemu-system-x86 \
        qemu-utils \
        expect \
        socat \
        curl \
        ca-certificates \
        bzip2 \
        procps \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /vm
