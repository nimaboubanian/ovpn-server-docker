#!/usr/bin/env bash
# build.sh — build the image via buildx on the host network (the host runs
# its VPN through wg-quick, so all egress including the registry is direct).
set -euo pipefail

BUILDER="ovpn-build"
IMAGE="${IMAGE:-openvpn-server:latest}"

# The layer cache lives in the builder container: reuse one named builder so
# builds don't re-download base images. network=host because buildkit's
# default bridge cannot resolve DNS on this host.
if ! docker buildx inspect "$BUILDER" >/dev/null 2>&1; then
    docker buildx create --name "$BUILDER" --driver docker-container \
        --driver-opt network=host >/dev/null
fi

export BUILDX_BUILDER="$BUILDER"
docker buildx build --load -t "$IMAGE" "$@" .
