# syntax=docker/dockerfile:1

# Caddy with the FlowGuard plugin, for containers and Kubernetes. See
# "Run on Kubernetes" in the README.
#
# Build a released version of the plugin:
#
#   docker build -f caddy/Dockerfile --build-arg FLOWGUARD_VERSION=0.33.1 -t flowguard-caddy .
#
# Without FLOWGUARD_VERSION, the plugin and FlowGuard are built from this
# checkout and report their version as "dev" to the control panel.

ARG GO_IMAGE=golang:1.27-alpine
ARG CADDY_IMAGE=caddy:2.11-alpine

FROM ${GO_IMAGE} AS build

# Keep in step with caddy/go.mod and the Caddy build in .github/workflows/ci.yml.
ARG CADDY_VERSION=v2.11.7
ARG XCADDY_VERSION=v0.4.7
ARG FLOWGUARD_VERSION=

# The golang images pin GOTOOLCHAIN to the image's Go version; let go.mod pick
# a newer patch release when it requires one.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto \
    XCADDY_GO_BUILD_FLAGS="-trimpath -ldflags=-s"

WORKDIR /src
COPY . .

RUN set -eu; \
    if [ -n "${FLOWGUARD_VERSION}" ]; then \
        set -- --with "go.chief.tools/flowguard-proxy/caddy@v${FLOWGUARD_VERSION#v}"; \
    else \
        set -- --with go.chief.tools/flowguard-proxy/caddy=./caddy --replace go.chief.tools/flowguard-proxy=.; \
    fi; \
    go run "github.com/caddyserver/xcaddy/cmd/xcaddy@${XCADDY_VERSION}" build "${CADDY_VERSION}" \
        --output /out/caddy "$@"; \
    /out/caddy list-modules | grep -qx http.handlers.flowguard

FROM ${CADDY_IMAGE}

COPY --from=build /out/caddy /usr/bin/caddy
