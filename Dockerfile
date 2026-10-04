ARG branch=stable

# ---------------------------------------------------------------------------
# Stage 1: build webcrack from a pinned upstream commit on Node 24 LTS.
# Node image pinned by digest (node:24-bookworm, v24.21.0); same Debian release as the AL base,
# so the node binary and the compiled isolated-vm addon run unchanged in stage 2.
# ---------------------------------------------------------------------------
FROM docker.io/library/node:24-bookworm@sha256:5a750d3be5e5c80275f8c9a5367c3aed99c2875656590c8d0701c7ee687f5f0a AS webcrack-build

# webcrack master, 19 commits past the 2.16.0 release. Change deliberately; the sample tests
# show what an upgrade changes.
ARG WEBCRACK_COMMIT=c80eec5f00622b86cea871d68349750ce950201f

WORKDIR /src
RUN git clone --quiet https://github.com/j4k0xb/webcrack.git . && \
    git checkout --quiet --detach "$WEBCRACK_COMMIT" && \
    test "$(git rev-parse HEAD)" = "$WEBCRACK_COMMIT"

# Install exactly what upstream's pnpm lockfile pins, build the library, then copy it with only
# its production dependencies into /opt/webcrack. Filters use the path: the workspace root is
# also named "webcrack", and building it would build the docs site and playground too.
RUN corepack enable && \
    pnpm install --frozen-lockfile --filter "./packages/webcrack..." && \
    pnpm --dir packages/webcrack run build && \
    pnpm --filter ./packages/webcrack deploy --prod --legacy /opt/webcrack && \
    printf '%s\n' "$WEBCRACK_COMMIT" > /opt/webcrack/BUILD_COMMIT

# isolated-vm is optional upstream but required here: it sandboxes the string-decoder
# evaluation that deobfuscation depends on. Fail the build if neither variant loads.
RUN cd /opt/webcrack && node -e " \
      const vms = ['isolated-vm-7', 'isolated-vm-6']; \
      const ok = vms.find(m => { try { require(m); return true; } catch { return false; } }); \
      if (!ok) { console.error('no isolated-vm variant loads'); process.exit(1); } \
      console.log('isolated-vm OK via', ok);"

# ---------------------------------------------------------------------------
# Stage 2: the AssemblyLine service.
# ---------------------------------------------------------------------------
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH=webcrack_.service.WebCrack

USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

COPY --from=webcrack-build /usr/local/bin/node /usr/local/bin/node
COPY --from=webcrack-build --chown=assemblyline:assemblyline /opt/webcrack /opt/webcrack

USER assemblyline
COPY --chown=assemblyline:assemblyline requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && \
    rm -rf ~/.cache/pip

WORKDIR /opt/al_service
COPY --chown=assemblyline:assemblyline . .

# Fail the build if webcrack does not run in the final image.
RUN node webcrack_/run_webcrack.mjs --self-test

ARG version=4.7.0.dev0
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml && \
    chown -R assemblyline:assemblyline /opt/al_service

USER assemblyline
