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

User/pass proxy over a ~30 ms link (so the round trips are visible):

```
┌────────────────────────────────────────────────┐
│ Comparison — averages (ms)                     │
├────────┬─────────┬───────────┬────────┬────────┤
│ PHASE  │ REGULAR │ PIPELINED │      Δ │     Δ% │
├────────┼─────────┼───────────┼────────┼────────┤
│ DNS    │       - │         - │      - │      - │
│ TCP    │    0.27 │      0.35 │  +0.08 │ +28.5% │
│ SOCKS5 │  190.67 │    102.92 │ -87.75 │ -46.0% │
│ TLS    │   62.86 │     62.71 │  -0.16 │  -0.2% │
│ Wait   │  121.66 │    112.78 │  -8.88 │  -7.3% │
│ TTFB   │  375.53 │    278.83 │ -96.70 │ -25.8% │
│ TTLB   │  375.70 │    279.00 │ -96.69 │ -25.7% │
└────────┴─────────┴───────────┴────────┴────────┘
```

Pipelining removes the 2 user/pass round trips: SOCKS5 drops ~2×RTT and TTFB/TTLB
drop by the same absolute amount. (Per-run tables are printed above this one.)

## Caveats

- **The win scales with the client→proxy RTT.** Pipelining saves 1 (no-auth) or
  2 (user/pass) round trips *to the proxy*. Against a local proxy (~0 ms) there
  is nothing to save — point it at your real remote proxy.
- **SOCKS5 includes the proxy→target connect**, because the server replies only
  after connecting to the destination. Pipelining removes only the pre-request
  round trips, so the SOCKS5 delta between the two clients is the clean signal.
