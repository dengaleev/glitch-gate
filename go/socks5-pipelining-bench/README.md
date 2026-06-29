# socks5-pipelining-bench

Fetches a URL through a SOCKS5 proxy and compares, side by side, the
strategies for bringing up the tunnel — **regular** (sequential), **pipelined**
(handshake in one write), **0-rtt** (handshake + first payload in one write),
and optionally **0-rtt+tfo** (that write carried in the TCP SYN) — printing a
per-phase latency breakdown via `net/http/httptrace`.

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

## 0-RTT data pipelining

Pipelining still waits for the CONNECT reply before the application sends its
first byte. The **0-rtt** mode goes one step further: it appends that first
payload (for an `https://` target, the TLS ClientHello) to the same write, sent
*before* any reply is read, so the proxy forwards it to the target the instant
the proxy→target connection opens — removing one more client↔proxy round trip.
The **0-rtt+tfo** mode additionally carries that single write in the TCP SYN
(TCP Fast Open), removing the proxy TCP-handshake round trip too.

Both 0-rtt modes are provided by the sibling
[`../socks5-0rtt-pipelining`](../socks5-0rtt-pipelining) package (this module
imports it via a local `replace`). See its README for the design, the
early-data interop story, and the replay-safety policy.

## Usage

```sh
go run . socks5://user:pass@proxy-host:1080          # regular, pipelined, 0-rtt
go run . -tfo socks5://user:pass@proxy-host:1080     # + 0-rtt+tfo
```

```
-target string   URL to fetch (default: Cloudflare cdn-cgi/trace)
-n int           measured requests per client (default 3)
-timeout dur     per-request timeout (default 30s)
-insecure        skip TLS certificate verification
-no-warmup       skip the warm-up request
-tfo             also measure a 0-rtt+TCP Fast Open client
```

The proxy URL is the only argument (`socks5://` or `socks5h://`; port defaults to
1080). Credentials trigger user/pass auth. The modes are interleaved each
iteration so none eats network warm-up bias.

> **TFO prerequisites.** `-tfo` needs OS support on both ends
> (`net.ipv4.tcp_fastopen`) and a TFO-capable proxy; otherwise it transparently
> falls back to a normal connection (no SYN-data win). The real benefit also
> requires a *warm* cookie — the first connection to a proxy always falls back.

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

**The deferred modes report SOCKS5 ≈ 0.** For `0-rtt` (and `0-rtt+tfo`) the
handshake is not performed in `DialContext` — it rides along with the first
application write (the TLS ClientHello) — so its cost folds into the TLS/Wait/TTFB
measurement rather than the SOCKS5 column. For `0-rtt+tfo` the TCP connect is
deferred too, so its TCP column is ≈ 0 as well. **TTFB/TTLB is the metric to
compare across modes;** the per-phase split is informative only within the
non-deferred (regular/pipelined) modes. The summary line prints each mode's TTFB
relative to regular.

## Example

The `regular`/`pipelined` columns below are a measured run against a real ~89 ms
link (`-n 10`); the `0-rtt` column is the **expected shape** (the harness here
has no high-latency proxy to measure, but see the sibling package's in-process
latency demonstration):

```
┌────────┬─────────┬───────────┬───────┐
│ PHASE  │ REGULAR │ PIPELINED │ 0-RTT │
├────────┼─────────┼───────────┼───────┤
│ TCP    │   88.92 │     87.35 │ ~88   │
│ SOCKS5 │  455.07 │    374.70 │  0.00 │   ← handshake folded into TLS/Wait
│ TLS    │  198.81 │    200.20 │ ~288  │   ← now carries ~1 RTT of SOCKS handshake
│ TTFB   │  928.98 │    856.88 │ ~770  │
│ TTLB   │  929.27 │    857.40 │ ~771  │
└────────┴─────────┴───────────┴───────┘

TTFB vs regular:   pipelined -7.8%   0-rtt ~-17%
```

Pipelining removes the no-auth greeting round trip (~1×RTT, ≈ the TCP figure);
0-rtt removes a *second* round trip — the wait-for-CONNECT-reply-then-send — so
its TTFB drops by roughly another RTT below pipelined. The SOCKS5 column is 0 for
0-rtt because the handshake now overlaps the TLS phase; read TTFB/TTLB.
(Per-run tables print above this one; a user/pass proxy saves an extra round trip.)

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
- **Occasional spikes skew the average.** A real proxy will now and then take
  ~1 s to reach the target (e.g. a dropped SYN getting retransmitted), and that
  lands in the `SOCKS5` column. Such outliers pull the **mean** up
  disproportionately — and they rarely hit both clients equally — so read the
  effect from the per-run spread, not just the headline `avg`. Outlier-discounted
  (median), the steady saving is ~1 RTT (no-auth) / ~2 RTT (user/pass): e.g. one
  50-sample run measured ~87 ms (no-auth) and ~172 ms (user/pass) against an
  ~88 ms link.
