FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils openssh-client socat iproute2 python3 python3-venv python3-apt curl ca-certificates openssl age && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /image /work && chmod 700 /work && curl -fsSL --retry 2 https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img -o /image/base.img && curl -fsSL https://cloud-images.ubuntu.com/noble/current/SHA256SUMS -o /image/SHA256SUMS && cd /image && grep 'noble-server-cloudimg-amd64.img$' SHA256SUMS | sed 's/noble-server-cloudimg-amd64.img/base.img/' | sha256sum -c -
CMD ["sleep", "infinity"]
