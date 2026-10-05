# socks0

A Go SOCKS5 client and server (plus SOCKS4/4a and Tor RESOLVE) built for fast
cold dials. The client sends the whole handshake in one write (**L1**) and can
send the first data with it (**L2**). The server cannot lose pipelined or early
bytes. Stdlib only, MIT, Go 1.26.

## Why

Measured in [`../socks5-zero-rtt-bench`](../socks5-zero-rtt-bench) on Linux
netem with an 80 ms client↔proxy RTT. Round trips include the TCP handshake.

| client | RTT no-auth | RTT user/pass | p50 |
| --- | --- | --- | --- |
| x/net/proxy, txthinking, wzshiming, gosocks5, sing | 4 | 5 | 361 ms |
| outline-sdk (the only other L1 client) | 3 | 3 | 281 ms |
| **socks0 L1** (`ModePipelined`, default) | 3 | 3 | 281 ms |
| **socks0 L1+L2** (`ModeEarly`) | **2** | **2** | **200 ms** |
| socks0 L1+L2 + TCP Fast Open (`FastOpenDial`, warm cookie) | 1 | 1 | — |

socks0 has the fewest allocs/op of the 11 clients measured. `socks0/server`
passes every cell of the bench's L1/L2 readiness matrix, where sing and GOST
lose early data. It relays with splice on Linux, at 0 allocs per byte.

## Packages

| package | contents |
| --- | --- |
| `socks0` | the client: `Dialer` (CONNECT, UDP ASSOCIATE, BIND, Tor RESOLVE, SOCKS4/4a, TFO); `Client`/`Conn`, which run the handshake over any conn, like `tls.Client`; typed errors and `KindOf`; `ClientTrace` and `Timings`; `FromURL` |
| `socks0/wire` | an allocation-free codec for every message in both directions that never over-reads |
| `socks0/server` | a `net/http`-shaped server with handlers, auth, a UDP relay, limits and `ServerTrace`; `DefaultFilter` blocks SSRF and DNS rebinding |

## Quick start

```go
d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"} // L1
// d.Config = &socks0.Config{Mode: socks0.ModeEarly} // L2: handshake + request in one segment
tr := &http.Transport{DialContext: d.DialContext}

d, err := socks0.FromURL(u) // socks5h://user:pass@host:1080, socks5s://…, socks4a://…
```

```go
s := &server.Server{Addr: ":1080", Auth: []server.Authenticator{server.UserPass{Users: users}}}
go s.ListenAndServe()
defer s.Shutdown(ctx)
```

## Before you switch

- With `ModeEarly`, `DialContext` returns before the proxy answers, and errors
  come from the first `Read`. So don't use it for latency probes, monitoring or
  failover. Use it only with servers that keep early data, which excludes sing,
  sing-box and GOST.
- `socks5://` resolves names **locally**, as curl does. Use `socks5h://` for
  Tor and for anything private.
- `errors.Is(err, syscall.EHOSTUNREACH)` also matches a proxy REP 04, and the
  same goes for 03, 05 and 06. Check `*socks0.ReplyError` or `KindOf` first.
- `Config.HandshakeTimeout` defaults to 30 s when the ctx has no deadline. A
  negative value means no limit.

## Quality

- Fuzzed codec and entry points.
- Coverage: 100% in `wire`, 97.6% in the client, 96.0% in the server.
- `-race` on macOS and Linux.
- An interop matrix in the bench: 3 modes × 9 servers, and every bench client against `socks0/server`.
- Independent spec verification, adversarial tests and a security review. Each
  fix has a regression test.

Design, decisions and how to run the Linux-only tests: [DESIGN.md](DESIGN.md).
