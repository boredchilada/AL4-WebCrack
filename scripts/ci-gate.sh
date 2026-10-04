#!/usr/bin/env bash
# Run lint, type checks and tests inside a built service image.
# Usage: scripts/ci-gate.sh <image> [docker|podman]
#
# The repo is copied in with `cp` rather than bind-mounted, so this also works when the CI job
# drives a Docker daemon it doesn't share a filesystem with.
set -euo pipefail

image="$1"
engine="${2:-docker}"

cid=$("$engine" create "$image" sleep infinity)
trap '"$engine" kill "$cid" >/dev/null 2>&1; "$engine" rm -f "$cid" >/dev/null' EXIT
"$engine" start "$cid" >/dev/null
"$engine" cp . "$cid:/tmp/src"
"$engine" exec -u root "$cid" chown -R assemblyline:assemblyline /tmp/src
"$engine" exec -w /tmp/src "$cid" bash -c '
  set -euo pipefail
  pip install --quiet --no-cache-dir --user -r tests/requirements.txt
  ruff check --no-cache .
  pyright
  pytest -p no:cacheprovider -v
'
