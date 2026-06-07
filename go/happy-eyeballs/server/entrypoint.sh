#!/bin/sh
set -e

# Silently drop inbound IPv6 SYNs to :8080 so the client's IPv6 connect stalls
# (no RST) instead of failing fast -- the condition that triggers Go's fallback.
nft add table ip6 filter
nft add chain ip6 filter input '{ type filter hook input priority 0; policy accept; }'
nft add rule ip6 filter input tcp dport 8080 drop

exec /usr/local/bin/server
