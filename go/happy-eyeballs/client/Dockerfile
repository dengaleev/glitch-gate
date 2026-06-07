# Build context is the module root so go.mod is available.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY client/ ./client/
RUN CGO_ENABLED=0 go build -o /out/client ./client

FROM alpine:3.21
COPY --from=build /out/client /usr/local/bin/client
ENTRYPOINT ["/usr/local/bin/client"]
