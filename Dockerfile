# syntax=docker/dockerfile:1

# FlowGuard for containers, such as a sidecar of the ingress controller on
# Kubernetes. See "Run on Kubernetes" in the README.
#
#   docker build --build-arg VERSION=0.34.0 -t flowguard .
#
# The image runs as a non-root user and holds no iptables, so run FlowGuard
# with --no-redirect and send traffic to its ports yourself.

ARG GO_IMAGE=golang:1.27-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot

FROM --platform=${BUILDPLATFORM} ${GO_IMAGE} AS build

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH

# The golang images pin GOTOOLCHAIN to the image's Go version; let go.mod pick
# a newer patch release when it requires one.
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# The same flags as bin/build.sh, which builds the packages.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" go build \
        -mod=readonly -trimpath -buildvcs=false -tags=netgo,osusergo \
        -ldflags="-s -w -X main.Version=${VERSION}" \
        -o /out/flowguard . && \
    install -d -m 0755 /out/data

FROM ${RUNTIME_IMAGE}

COPY --from=build /out/flowguard /usr/local/bin/flowguard

# The configuration, which holds the host key, and the downloaded IP lists and
# IP database. Mount a volume here when the root filesystem is read-only.
COPY --from=build --chown=65532:65532 /out/data /var/lib/flowguard

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/flowguard"]
CMD ["run", "--no-redirect", "--config", "/var/lib/flowguard/config.json", "--cache-dir", "/var/lib/flowguard/cache"]
