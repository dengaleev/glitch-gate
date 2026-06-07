# Build context is the module root so go.mod is available.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY server/ ./server/
RUN CGO_ENABLED=0 go build -o /out/server ./server

# nftables (+ NET_ADMIN from compose) lets the entrypoint drop IPv6 SYNs.
FROM alpine:3.21
RUN apk add --no-cache nftables
COPY server/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --from=build /out/server /usr/local/bin/server
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
