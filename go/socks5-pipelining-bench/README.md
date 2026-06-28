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

## Example

A no-auth proxy over a real ~85 ms link, 3 requests each:

```
┌────────────────────────────────────────────────┐
│ Comparison — averages (ms)                     │
├────────┬─────────┬───────────┬────────┬────────┤
│ PHASE  │ REGULAR │ PIPELINED │      Δ │     Δ% │
├────────┼─────────┼───────────┼────────┼────────┤
│ DNS    │    5.81 │      3.90 │  -1.91 │ -32.8% │
│ TCP    │   94.43 │     87.39 │  -7.04 │  -7.5% │
│ SOCKS5 │  456.62 │    383.53 │ -73.08 │ -16.0% │
│ TLS    │  200.64 │    206.08 │  +5.44 │  +2.7% │
│ Wait   │  186.63 │    202.42 │ +15.78 │  +8.5% │
│ TTFB   │  944.24 │    883.42 │ -60.82 │  -6.4% │
│ TTLB   │  944.50 │    883.87 │ -60.63 │  -6.4% │
└────────┴─────────┴───────────┴────────┴────────┘
```

Pipelining removes the no-auth greeting round trip: SOCKS5 drops ~1×RTT (~73 ms)
and TTFB/TTLB fall by the same amount. DNS/TCP/TLS/Wait are untouched by
pipelining — their deltas here are just run-to-run noise. (Per-run tables print
above this one; a user/pass proxy saves 2 round trips instead of 1.)

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
