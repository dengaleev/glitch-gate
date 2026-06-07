# Happy Eyeballs

A minimal Go program that shows how the standard library implements the
**Happy Eyeballs** algorithm ([RFC 8305](https://www.rfc-editor.org/rfc/rfc8305))
inside `net.Dialer`.

When a hostname resolves to both IPv6 (`AAAA`) and IPv4 (`A`) addresses, Go's
dialer tries IPv6 **first**. If that TCP connect does not complete within
`Dialer.FallbackDelay` (300ms by default), it starts racing IPv4 in parallel.
The first connection to succeed wins; the loser is cancelled.

This demo issues a single HTTP request and uses `net/http/httptrace` to log
every connection attempt with a timestamp, so you can watch the IPv6 attempt
stall and IPv4 take over after the fallback delay.

## What it demonstrates

The accompanying Docker Compose stack runs a mock server reachable as
`mock.test` on **both** an IPv6 and an IPv4 address. The server uses an
`nftables` rule to silently **drop inbound IPv6 SYNs** to port 8080, so the
IPv6 connect stalls (no `RST`, just a timeout) — exactly the condition that
triggers the IPv4 fallback.

```sh
docker compose up --build --abort-on-container-exit --exit-code-from client
```

Expected client output:

```
20:58:28.642856 requesting http://mock.test:8080 (fallback-delay=300ms)
20:58:28.643254 [      0s] resolved: 2001:db8:1::10, 172.28.0.10
20:58:28.643277 [      0s] -> connect  [2001:db8:1::10]:8080
20:58:28.944300 [   301ms] -> connect  172.28.0.10:8080
20:58:28.945320 [   302ms] <- ok       172.28.0.10:8080
20:58:28.945414 [   303ms] winner: 172.28.0.10:8080
20:58:28.945739 [   303ms] <- fail     [2001:db8:1::10]:8080: operation was canceled
20:58:28.947230 [   304ms] 200 OK, served by 172.28.0.10:8080
```

Notice the ~300ms gap between the IPv6 and IPv4 `-> connect` lines — that is
`FallbackDelay` in action. Each line carries a wall-clock timestamp plus an
elapsed-since-start marker (`[ ... ]`). Tear it down with `docker compose down -v`.

## Running the client directly

The client is dependency-free (standard library only):

```sh
go run github.com/dengaleev/glitch-gate/go/happy-eyeballs/client@latest -url http://example.com
```

Flags:

- `-url`: URL to request; its host should resolve to both IPv6 and IPv4 (default `http://mock.test:8080`)
- `-fallback-delay`: `Dialer.FallbackDelay`, the IPv6→IPv4 race delay (default `300ms`)

Try `-fallback-delay 1s` against the Compose stack to watch the fallback take a
full second, or `-fallback-delay 0` to see Go use its 300ms default.

## How it works

| Piece | Role |
| --- | --- |
| `client/main.go` + `client/Dockerfile` | The client — the demo itself. Builds an `http.Transport` over a `net.Dialer` and logs attempts via `httptrace`. |
| `server/main.go` + `server/Dockerfile` | A tiny dual-stack HTTP server; reports the local address that served each request. |
| `server/entrypoint.sh` | Adds an `nftables` rule dropping inbound IPv6 TCP to `:8080` so the IPv6 path stalls, then starts the server. |
| `compose.yml` | A dual-stack bridge network mapping `mock.test` to both families. |

The two containerized components are symmetric — each lives in its own
directory with its `main.go` and `Dockerfile`. The shared `go.mod`,
`compose.yml`, and this README sit at the module root. Everything is
standard-library only.

### Why the IPv6 subnet is `2001:db8::`

Go orders resolved addresses per [RFC 6724](https://www.rfc-editor.org/rfc/rfc6724).
A private ULA prefix (`fd00::/8`) sorts *below* private IPv4, so Go would try
IPv4 first and never exercise the fallback. The demo uses the `2001:db8::/32`
documentation prefix, which sorts as global unicast and is preferred over the
IPv4 address — so IPv6 is genuinely tried first.

> Requires Docker with IPv6 enabled (the Compose file sets `enable_ipv6: true`)
> and grants the server `NET_ADMIN` so it can install the `nftables` rule.
