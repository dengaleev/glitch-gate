# socks5-pipelining-bench

Fetches a URL through a SOCKS5 proxy and compares a **regular** (sequential)
SOCKS5 handshake against a **pipelined** one, printing a per-phase latency
breakdown via `net/http/httptrace`.

## Handshake pipelining

The SOCKS5 client handshake is normally 2 round trips (no-auth) or 3 (user/pass):
greeting → method reply → [auth → auth reply] → request → reply. When the client
commits to a single auth method up front, the server's method reply is
predictable, so it can write the greeting + (optional auth) + CONNECT request in
**one packet** and read the replies in order — collapsing the handshake to one
round trip.

Both handshakes are built from `github.com/txthinking/socks5`'s wire primitives:
the regular path is byte-for-byte what `socks5.Client.Dial` sends; the pipelined
path batches the writes.

## Usage

```sh
go run . socks5://user:pass@proxy-host:1080
```

```
-target string   URL to fetch (default: Cloudflare cdn-cgi/trace)
-n int           measured requests per client (default 3)
-timeout dur     per-request timeout (default 30s)
-insecure        skip TLS certificate verification
-no-warmup       skip the warm-up request
```

The proxy URL is the only argument (`socks5://` or `socks5h://`; port defaults to
1080). Credentials trigger user/pass auth.

## Metrics (ms)

| Column | Meaning |
| --- | --- |
| DNS    | proxy hostname resolution (`-` if the proxy is an IP) |
| TCP    | TCP connect to the proxy |
| SOCKS5 | SOCKS5 handshake (TCP-connected → CONNECT reply) |
| TLS    | TLS handshake to the target, through the tunnel (https) |
| Wait   | server processing: connection ready → first byte |
| TTFB   | time to first byte |
| TTLB   | time to last byte (total) |

DNS/TCP/SOCKS5 are timed in a custom `DialContext`; TLS/TTFB come from
`httptrace`. Keep-alives are off and HTTP/1.1 is forced so each request dials
fresh.

DNS is the lookup of the **proxy's** hostname (`-` for an IP proxy). The target
is always handed to the proxy to resolve, so its DNS lands inside SOCKS5, not the
DNS column — and `socks5h://` therefore behaves the same as `socks5://` here.

## Example

A no-auth proxy over a real ~89 ms link, `-n 10`:

```
┌────────────────────────────────────────────────┐
│ Comparison — averages (ms)                     │
├────────┬─────────┬───────────┬────────┬────────┤
│ PHASE  │ REGULAR │ PIPELINED │      Δ │     Δ% │
├────────┼─────────┼───────────┼────────┼────────┤
│ DNS    │    3.73 │      4.03 │  +0.30 │  +8.1% │
│ TCP    │   88.92 │     87.35 │  -1.57 │  -1.8% │
│ SOCKS5 │  455.07 │    374.70 │ -80.37 │ -17.7% │
│ TLS    │  198.81 │    200.20 │  +1.39 │  +0.7% │
│ Wait   │  182.36 │    190.47 │  +8.11 │  +4.4% │
│ TTFB   │  928.98 │    856.88 │ -72.10 │  -7.8% │
│ TTLB   │  929.27 │    857.40 │ -71.87 │  -7.7% │
└────────┴─────────┴───────────┴────────┴────────┘
```

Pipelining removes the no-auth greeting round trip: SOCKS5 drops ~1×RTT (~80 ms,
≈ the TCP figure) and TTFB/TTLB fall by the same amount. DNS/TCP/TLS/Wait are
untouched by pipelining — with enough samples their deltas converge to ~0. (Per-run
tables print above this one; a user/pass proxy saves 2 round trips instead of 1.)

## Caveats

- **The win scales with the client→proxy RTT.** Pipelining saves 1 (no-auth) or
  2 (user/pass) round trips *to the proxy*, so the benefit grows with link
  latency. Against a local proxy (~0 ms) there is nothing to save.
- **SOCKS5 includes the proxy→target connect.** The server replies only after
  connecting to the destination, so that connect — often the largest and most
  variable part — lands in the SOCKS5 column for both clients. Pipelining removes
  only the pre-request round trips, so the SOCKS5 delta is the signal; with a
  small `-n` the target-connect variance can mask (or briefly invert) it, so
  raise `-n` to average it out.
