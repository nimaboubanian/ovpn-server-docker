# openvpn-server: Alpine's openvpn (2.7.x in `main`) plus sing-box as the egress
# chain. No build stage for openvpn — the distro package is exactly what the spec
# assumes, and easy-rsa is deliberately not installed.
#
# Base images come via the ArvanCloud mirror: Docker Hub 403s this host's
# egress (docker.io/registry-1.docker.io), gcr.io mirror too.
FROM docker.arvancloud.ir/library/alpine:3.24 AS singbox-build

ARG SINGBOX_VERSION=1.14.2
ARG TARGETARCH

RUN apk add --no-cache curl ca-certificates
RUN set -eux; \
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 2 -o /tmp/sing_box.tar.gz \
        "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl.tar.gz"; \
    tar -xzf /tmp/sing_box.tar.gz -C /tmp \
        "sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box"; \
    mv "/tmp/sing-box-${SINGBOX_VERSION}-linux-${TARGETARCH}-musl/sing-box" /usr/local/bin/sing-box; \
    chmod +x /usr/local/bin/sing-box; \
    sing-box version

FROM docker.arvancloud.ir/library/alpine:3.24

RUN apk add --no-cache openvpn openssl bash tini iproute2 jq

COPY --from=singbox-build /usr/local/bin/sing-box /usr/local/bin/sing-box

COPY --chmod=755 scripts /usr/local/bin

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]