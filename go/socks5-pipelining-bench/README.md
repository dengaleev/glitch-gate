# socks5-pipelining-bench

A tiny CLI that fetches a URL through a SOCKS5 proxy and compares a **regular
(sequential) SOCKS5 handshake** against a **pipelined** one — greeting +
(optional auth) + `CONNECT` request written in a single packet — reporting a
per-phase latency breakdown via `net/http/httptrace`.

It does `-n` requests with each client (interleaved) and prints conn-establish,
SOCKS5-handshake, TLS, server-wait, TTFB and TTLB metrics side by side.

## Background

The RFC 1928 / RFC 1929 client handshake is normally `2` round trips (no-auth)
or `3` (user/pass): greeting → method reply → [auth → auth reply] → request →
reply. When the client commits to **exactly one auth method** up front it can
predict the server's method selection, so it may write the greeting, auth and
request **back-to-back** and read the replies in order — collapsing the
handshake to **one round trip**. See
[`../socks5-libs-comparison`](../socks5-libs-comparison/README.md#handshake-pipelining-a-client-latency-optimization)
for which libraries support this.

Both handshakes here are built from `github.com/txthinking/socks5`'s exported
wire primitives. The **regular** path is byte-for-byte what `socks5.Client.Dial`
sends; the **pipelined** path sends the same bytes in one `Write`.

## Usage

```sh
go run github.com/dengaleev/glitch-gate/go/socks5-pipelining-bench@latest \
    socks5://user:pass@proxy-host:1080
```

```
socks5-pipelining-bench [flags] socks5://[user:pass@]host:port

  -target string   destination URL (default "https://www.cloudflare.com/cdn-cgi/trace")
  -n int           measured requests per client (default 3)
  -timeout dur     per-request timeout (default 30s)
  -insecure        skip TLS certificate verification
  -no-warmup       skip the unmeasured warm-up request
```

- The proxy URL is the only positional argument (`socks5://` or `socks5h://`;
  port defaults to `1080`). Credentials in the URL trigger user/pass auth.
- The default target is Cloudflare's `cdn-cgi/trace` (returns `ip=`, `colo=`,
  etc.); the tool prints the `ip`/`colo` from a warm-up request as a sanity line.

## Metrics

All times in milliseconds.

| Column | Meaning |
| --- | --- |
| `DNS`    | Proxy hostname resolution (`-` if the proxy is an IP). |
| `TCP`    | TCP connection establishment **to the proxy**. |
| `SOCKS5` | SOCKS5 handshake: from TCP-connected to the `CONNECT` reply. |
| `TLS`    | TLS handshake to the target, through the tunnel (https only). |
| `Wait`   | Server processing: connection-ready → first response byte. |
| `TTFB`   | Time to first byte, from request start. |
| `TTLB`   | Time to last byte (full body read), from request start. |

DNS/TCP/SOCKS5 are timed inside a custom `http.Transport.DialContext`; TLS and
TTFB come from `httptrace.ClientTrace`; TTLB is measured around the body read.
Keep-alives are disabled and HTTP/1.1 is forced so every request performs a full
fresh dial + handshake.

## Example

Against a proxy with ~30 ms link latency (so round trips are visible), user/pass auth:

```
Regular (sequential handshake)
  run  DNS   TCP  SOCKS5    TLS    Wait    TTFB    TTLB
    1    -  0.38  188.33  63.02  113.72  365.56  365.74
    2    -  0.31  189.57  62.97  113.63  366.56  366.71
    3    -  0.23  185.56  62.99  113.02  361.87  362.11
  avg    -  0.31  187.82  62.99  113.46  364.66  364.86

Pipelined (greeting+auth+request in one write)
  run  DNS   TCP  SOCKS5    TLS    Wait    TTFB    TTLB
    1    -  0.33   91.85  62.97  115.69  270.94  271.11
    2    -  0.19   92.43  62.91  112.59  268.19  268.31
    3    -  0.15   91.68  63.04  113.39  268.36  268.52
  avg    -  0.23   91.99  62.97  113.89  269.16  269.31

Comparison (averages)
   phase  regular  pipelined   delta  delta%
     DNS        -          -       -       -
     TCP     0.31       0.23   -0.08  -25.8%
  SOCKS5   187.82      91.99  -95.84  -51.0%
     TLS    62.99      62.97   -0.02   -0.0%
    Wait   113.46     113.89   +0.43   +0.4%
    TTFB   364.66     269.16  -95.50  -26.2%
    TTLB   364.86     269.31  -95.54  -26.2%
```

Here pipelining removes the 2 user/pass round trips: SOCKS5 drops by ~2×RTT and
TTFB/TTLB drop by the same absolute amount.

## Reading the results — two caveats

1. **The win scales with the client→proxy RTT.** Pipelining saves `1` (no-auth)
   or `2` (user/pass) *round trips to the proxy*. Against a **local** proxy
   (≈0 ms RTT) there is essentially nothing to save and the numbers will look
   equal or noisy. Run it against your real, remote proxy to see the benefit.
2. **The `SOCKS5` phase includes the proxy→target connect.** A SOCKS5 server
   sends its `CONNECT` reply only *after* it has connected to the destination,
   so that connect time (and its variance) lands in the `SOCKS5` column for both
   clients. Pipelining doesn't change it; it only removes the *pre-request*
   round trips. The `SOCKS5` delta between the two clients is the clean signal.
