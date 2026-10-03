# syntax=docker/dockerfile:1
# Context: module root (see ../run.sh).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /bench .

# Network only: enough for `topo.sh check`.
FROM alpine:3.23 AS net
RUN apk add --no-cache iproute2 iproute2-ss iproute2-tc ethtool iputils socat tcpdump util-linux-misc
COPY netem/topo.sh /usr/local/bin/topo.sh
ENTRYPOINT ["/usr/local/bin/topo.sh"]

FROM net
COPY --from=build /bench /usr/local/bin/bench
