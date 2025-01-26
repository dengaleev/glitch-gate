FROM caddy:builder AS builder

RUN xcaddy build \
    --with github.com/pberkel/caddy-storage-redis \
    --with github.com/mholt/caddy-ratelimit

FROM caddy:latest

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
