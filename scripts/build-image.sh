#!/usr/bin/env bash
# Build the service image on the exact digest that `stable` points to right now, and record it.
# Usage: scripts/build-image.sh <image:tag> <version> [docker|podman]
set -euo pipefail

target="$1"
version="$2"
engine="${3:-docker}"
base=docker.io/cccs/assemblyline-v4-service-base

"$engine" pull --quiet "$base:stable" >/dev/null
digest=$("$engine" image inspect "$base:stable" --format '{{index .RepoDigests 0}}')
digest="${digest##*@}"
test -n "$digest"

"$engine" build \
  --build-arg branch="stable@$digest" \
  --build-arg version="$version" \
  --label "org.opencontainers.image.base.name=$base:stable@$digest" \
  --label "org.opencontainers.image.version=$version" \
  --label "org.opencontainers.image.revision=$(git rev-parse HEAD)" \
  -t "$target" .
echo "built $target on $base@$digest"
