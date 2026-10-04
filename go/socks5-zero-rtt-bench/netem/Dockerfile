# syntax=docker/dockerfile:1
# Context: the parent go/ dir, for the ../socks0 replace (see ../run.sh).
FROM golang:1.27-alpine AS build
WORKDIR /src/socks5-zero-rtt-bench
COPY socks0/go.mod /src/socks0/
COPY socks5-zero-rtt-bench/go.mod socks5-zero-rtt-bench/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY socks0/ /src/socks0/
COPY socks5-zero-rtt-bench/ ./
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /bench .

# Network only: enough for `topo.sh check`.
FROM alpine:3.23 AS net
RUN apk add --no-cache iproute2 iproute2-ss iproute2-tc ethtool iputils socat tcpdump util-linux-misc
COPY socks5-zero-rtt-bench/netem/topo.sh /usr/local/bin/topo.sh
ENTRYPOINT ["/usr/local/bin/topo.sh"]

FROM net
COPY --from=build /bench /usr/local/bin/bench
