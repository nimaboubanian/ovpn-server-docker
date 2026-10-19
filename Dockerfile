# openvpn-server: Alpine's openvpn (2.7.x in `main`) plus hev-socks5-tunnel as the
# egress chain. No build stage for openvpn — the distro package is exactly what the
# spec assumes, and easy-rsa is deliberately not installed.
#
# Base images come via the ArvanCloud mirror: Docker Hub 403s this host's
# egress (docker.io/registry-1.docker.io), gcr.io mirror too.
FROM docker.arvancloud.ir/library/alpine:3.24 AS hev-build

ARG HEV_VERSION=2.14.4

RUN apk add --no-cache gcc make musl-dev git linux-headers
RUN set -eux; \
    git clone --depth 1 --branch "${HEV_VERSION}" --recursive --shallow-submodules \
        https://github.com/heiher/hev-socks5-tunnel /src; \
    sed -i 's/^LDFLAGS=/LDFLAGS=-static /' /src/Makefile; \
    make -C /src -j"$(nproc)"; \
    install -m 755 /src/bin/hev-socks5-tunnel /usr/local/bin/hev-socks5-tunnel; \
    /usr/local/bin/hev-socks5-tunnel -v || true

FROM docker.arvancloud.ir/library/alpine:3.24

RUN apk add --no-cache openvpn openssl bash tini iproute2 jq

COPY --from=hev-build /usr/local/bin/hev-socks5-tunnel /usr/local/bin/hev-socks5-tunnel

COPY --chmod=755 scripts /usr/local/bin

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
