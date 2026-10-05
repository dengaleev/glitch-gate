# Go SOCKS5 Libraries — Comparison

Popularity, maintenance, features (especially UDP `ASSOCIATE`, which this repo's
[`socks5-udp-test`](../socks5-udp-test) needs), design and performance of Go SOCKS5
libraries. **Snapshot 2026‑06‑28** (versions and licenses re‑checked 2026‑10‑04);
stars and `imported by` drift.

## TL;DR

| If you need… | Use | Why |
| --- | --- | --- |
| **Client only**, TCP `CONNECT`, no deps | **`golang.org/x/net/proxy`** | Go team, stdlib‑only, `context`. **No UDP.** |
| **Server only**, maintained | **`things-go/go-socks5`** | Active `armon` fork; server UDP relay, middleware, `context`. |
| **Client + server + UDP**, zero deps | **`wzshiming/socks5`** | `CONNECT`/`BIND`/UDP both sides, `context`, clean API. |
| **Client + server + UDP**, battle‑tested | **`txthinking/socks5`** | Powers Brook/Hysteria. Dated API, 3 deps, no `context`. |
| **Low‑level primitives** | **`go-gost/gosocks5`** | Zero‑dep RFC 1928/1929 codecs + handshake; UDP primitives only. |
| Embedding in a **proxy platform** | **`sagernet/sing`** / **Outline SDK** | Toolkit‑grade, full UDP, heavy; `sing` is **GPL‑3.0**. |

For `socks5-udp-test`: `txthinking/socks5` (current) is sound; `wzshiming/socks5`
is the zero‑dep, `context`‑aware alternative; Outline's `transport/socks5` is the
best‑tested client‑only UDP dialer.

## Popularity & maintenance

| Library | Stars | Forks | `imported by` | Latest release / last commit | Status |
| --- | ---: | ---: | ---: | --- | --- |
| `golang.org/x/net/proxy` | ~3,000¹ | ~1,300¹ | **4,740** | `x/net` v0.59.0 (2026‑09‑08); actively maintained | ✅ Active (Go team) |
| `armon/go-socks5` | 2,100 | 551 | 423 | last commit 2016‑09‑02; no tags | ⛔ Unmaintained |
| `things-go/go-socks5` | 597 | 100 | 107 | v0.1.1 (2026‑03‑25) | ✅ Active |
| `txthinking/socks5` | 782 | 133 | 181 | last commit 2026‑06‑01 (no tags, pseudo‑versions) | ✅ Active (low‑volume) |
| `go-gost/gosocks5` | 25 | 19 | 68 | v0.5.0; last commit 2026‑05‑21 | ✅ Active (GOST core) |
| `wzshiming/socks5` | 131 | 31 | 21 | v0.8.0 (2026‑09‑16) | ✅ Active (solo) |
| `haxii/socks5` | 50 | 22 | 7 | v1.0.0 (2019‑07‑08) | ⛔ Dormant |
| `getlantern/go-socks5` | 13 | 4 | 6 | last commit 2017‑11‑14; no tags | ⛔ Dead |
| `sagernet/sing` (socks pkg) | 125² | 96² | 39 | v0.9.6 (2026‑09‑27); **GPL‑3.0** | ✅ Active |
| Outline SDK `transport/socks5` | 646³ | 180³ | ~0–2⁴ | v0.1.0‑rc1 / v0.0.23; repo push 2026‑06‑23 | ✅ Active (pre‑1.0) |
| `go-shadowsocks2/socks` | ~4,700³ | 1,488³ | 104 | v0.1.5 (2021‑04‑21); last commit 2024‑10‑20 | 🟡 Maintenance‑mode |

¹ Whole `golang/net` repo; 4,740 importers is the `proxy` package. ² `SagerNet/sing`;
dependent sing‑box has ~35,400 stars. ³ Parent repo. ⁴ Reach comes via the Outline
SDK; module moved to `golang.getoutline.org/sdk` (org Jigsaw‑Code → OutlineFoundation).

Notable users: **x/net/proxy** — Tor PTs, Psiphon, whatsmeow, nuclei/naabu, Cloud SQL
connectors, Beats, Packer. **armon** — frp, chisel, OONI, HyperShift. **things-go** —
Sliver, Caddy‑L4, NetBird, proxify. **txthinking** — Brook, Hysteria, Trojan‑Go,
RouteDNS, Snowflake. **gosocks5** — GOST, suo5. **wzshiming** — kt‑connect, surf.
**sing** — sing‑box, NekoBox. **go-shadowsocks2/socks** — Outline SS server, tun2socks, Clash forks.

## Feature matrix

| Library | Client | Server | UDP `ASSOCIATE` | `BIND` | SOCKS4/4a | User/Pass auth | GSSAPI | `context` | Custom dialer/resolver | Rules / ACL | Ext. deps |
| --- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `x/net/proxy` | ✅ | ❌ | ❌ | ❌⁵ | ❌ | ✅ | ❌ | ✅ | ✅ dialer | `PerHost` only | none |
| `armon/go-socks5` | ❌ | ✅ | ❌ (stub) | ❌ (stub) | ❌ | ✅ | ❌ | ✅ | ✅ both | ✅ `RuleSet` | `x/net` |
| `things-go/go-socks5` | ❌ | ✅ | ✅ **server** | ❌ (hook) | ❌ | ✅ | ❌ | ✅ | ✅ both | ✅ rules+middleware | `x/net` |
| `txthinking/socks5` | ✅ | ✅ | ✅ **both** | ⚠️ partial | ❌ | ✅ | ❌ | ❌ | ✅ dialer⁶ | via `Handler` | 3 |
| `go-gost/gosocks5` | ✅⁷ | ✅⁷ | ⚠️ primitives | ✅ server | ❌ | ✅ | ❌ | ⚠️ client‑dial | ❌ limited | ❌ | **none** |
| `wzshiming/socks5` | ✅ | ✅ | ✅ **both** | ✅ **both** | ❌⁸ | ✅ | ❌ | ✅ | ✅ extensive | auth callback | **none** |
| `haxii/socks5` | ❌ | ✅ | ✅ **server** | ❌ | ❌ | ✅ | ❌ | ⚠️ dial only | ✅ both | ✅ `RuleSet` | none |
| `getlantern/go-socks5` | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ | ⚠️ dial only | ✅ both | ✅ `RuleSet` | golog/netx |
| `sagernet/sing` socks | ✅ | ✅ | ✅ **both** | ⚠️ client only | ✅ | ✅ | ❌ | ✅ | ✅ dialer | ❌ (in app) | toolkit |
| Outline `transport/socks5` | ✅ | ❌ | ✅ **client** | ❌⁵ | ❌ | ✅ | ❌ | ✅ | ✅ endpoints | ❌ | toolkit |
| `go-shadowsocks2/socks` | ❌ | ⚠️ handshake | ⚠️ flag‑gated | ❌ | ❌ | ❌ (no‑auth) | ❌ | ❌ | ❌ | ❌ | none |

⁵ `BIND` constant exists but isn't usable. ⁶ Per‑client dialer hooks since mid‑2026
(PR #28). ⁷ Thin helpers: server does `CONNECT`/`BIND`; client does the method
handshake, you write the `Request`/read the `Reply`. ⁸ SOCKS5 and SOCKS5h, not SOCKS4.
All handle IPv4/IPv6/domain; **none implements GSSAPI**.

## UDP `ASSOCIATE` tiers

| Tier | Libraries | Notes |
| --- | --- | --- |
| **Full UDP, both client & server** | `txthinking/socks5`, `wzshiming/socks5`, `sagernet/sing` | Production‑grade relays on both sides. |
| **Client‑side UDP only** | Outline SDK `transport/socks5` | Clean `PacketListener`; 16 KiB cap, no fragmentation. |
| **Server‑side UDP only** | `things-go/go-socks5`, `haxii/socks5` | Built‑in server relay (no client). |
| **Primitives only (DIY relay)** | `go-gost/gosocks5`, `go-shadowsocks2/socks` | Datagram encode/decode exists; you wire the relay. |
| **No UDP at all** | `x/net/proxy`, `armon/go-socks5`, `getlantern/go-socks5` | `CONNECT`‑only. |

`x/net` UDP proposal [golang/go#32790](https://github.com/golang/go/issues/32790) is
closed/frozen, unimplemented.

## Per‑library notes

**`x/net/proxy`**
- Built on unexported `x/net/internal/socks` (~300 LOC); `SOCKS5()`, `FromURL()`,
  `FromEnvironment()`, `ContextDialer`, `PerHost`. Client/`CONNECT`/TCP only.

**`armon/go-socks5`**
- Turnkey server with pluggable auth, resolver, `RuleSet`, `AddressRewriter`;
  `BIND`/`ASSOCIATE` are stubs. No `go.mod`, legacy `x/net/context`; prefer `things-go`.

**`things-go/go-socks5`** (formerly `thinkgos/go-socks5`)
- Functional options, per‑command middleware, goroutine/buffer pools, built‑in
  server UDP relay; `BIND` is a hook. Only `x/net` at runtime; `testify` tests.

**`txthinking/socks5`**
- Raw primitives (`Negotiation`/`Request`/`Reply`/`Datagram`) + `DefaultHandle`
  server; UDP associations in `go-cache`, `LimitUDP` ties UDP to a live TCP association.
- No `context`, integer‑second positional timeouts, partial `BIND`; deps `miekg/dns`,
  `patrickmn/go-cache`, `txthinking/runnergroup`; light tests.

**`go-gost/gosocks5`**
- RFC codecs (`Request`, `Reply`, `Addr`, `UDPDatagram`, `UserPass*`) + `Selector`
  handshake `Conn`; server's UDP case is commented out (GOST relays itself).
- May 2026: allocation cuts, `sync.Pool`, benchmarks, security fixes.

**`wzshiming/socks5`**
- `CONNECT`/`BIND`/UDP on both sides; hooks `ProxyDial`/`ProxyListen`/
  `ProxyListenPacket`/`Resolver`/`BytesPool`; two server UDP modes; ACL = auth callback.

**`haxii/socks5`**
- `armon` + server UDP (`sync.Pool`); no fragmentation, UDP relay doesn't
  authenticate the sender, no UDP tests.

**`getlantern/go-socks5`**
- `armon` + `context` `Dial`, Lantern `golog`/`netx`; no reason to pick it.

**`sagernet/sing` `/protocol/socks`**
- SOCKS4/4a/5, UDP both sides, client `BIND`, pooled zero‑copy buffers, `HandlerEx` API.
- Not drop‑in: adopt `M.Socksaddr`, `N.Dialer`, `buf.Buffer`; no in‑package tests; GPL‑3.0‑or‑later.

**Outline SDK `transport/socks5`**
- `StreamDialer` + `PacketListener`, single‑write handshake, `netip`, Apache‑2.0, well tested.
- No server/`BIND`; UDP unfragmented, 16 KiB cap; pre‑1.0, depends on sibling `transport`.

**`go-shadowsocks2/socks`**
- ~200‑line block: address parsing (`MaxAddrLen = 259`) + no‑auth server `Handshake`
  with flag‑gated UDP. Not a general‑purpose choice.

## Design & performance

- **Zero ext. deps:** `wzshiming`, `gosocks5`, `haxii`, `go-shadowsocks2/socks`.
  **No `context`:** `txthinking`, `go-shadowsocks2/socks`.
- **Benchmarks:** only `gosocks5` ships them (`sync.Pool`, 1500‑byte relay buffers).
  `sing` is the most throughput‑oriented (zero‑copy buffers, vectorised I/O, `LazyConn`).
  `things-go`, `haxii`, Outline pool buffers; `armon`/`getlantern` plain `io.Copy`;
  `txthinking` no pooling; `x/net/proxy` returns the raw conn (no relay).

## Handshake pipelining

A sequential client spends 2 round trips (no‑auth) or 3 (user/pass) before the
tunnel is usable. A client that advertises **exactly one** auth method can write
greeting + [auth] + request in one `Write` and read the replies in order: 1 RTT.
Every client surveyed reads replies with `io.ReadFull` on the raw conn and builds
the request from the destination, so the deciding factor is how many methods it
advertises.

| Client | Advertises auth methods | Already pipelined? | Extend to pipeline | Why |
| --- | --- | :-: | --- | --- |
| **Outline SDK** `transport/socks5` | single (always) | ✅ **yes** | already done | **Reference impl**: assembles greeting+auth+request in one buffer, one `Write`, then ordered `io.ReadFull`. 1 RTT. |
| **`sagernet/sing`** socks | single (always) | ❌ | **easy** | `ClientHandshake5` already advertises one method (`[]byte{method}`); just an additive variant that concatenates the writes. |
| **`txthinking/socks5`** | single (always) | ❌ | **moderate** | Structurally ~90% there; only obstacle is that writes are split across the public `Negotiate()` + `Request()` methods. Add a new method (no breaking change). |
| **`go-gost/gosocks5`** | single (default selector); configurable | ❌ | moderate | Default selector offers one method, but the request write is *caller‑side* and auth is fused inside `Selector.OnSelected` — needs an API path change. |
| **`wzshiming/socks5`** | single (no‑auth) / **two (user/pass)** | ❌ | moderate | Clean injectable design, but the user/pass path advertises **both** `0x00`+`0x02`; must commit to a single method to pipeline that path. No‑auth path is already pipelinable. |
| **`golang.org/x/net/proxy`** | **two (user/pass via public API)** | ❌ | hard | `proxy.SOCKS5()` advertises **both** no‑auth and user/pass whenever auth is set, so auth can't be pipelined without a behavior change — in a *frozen, internal* package. Only the no‑auth path is naturally pipelinable. |

Server‑only libraries have no client handshake to optimize.

### Measured (2026‑10‑04, [`socks5-zero-rtt-bench`](../socks5-zero-rtt-bench))

- **Servers:** pipelining (L1) works everywhere. Early data (L2) is **lost** by
  `sagernet/sing` (parses via `bufio.Reader`, relays from the raw conn —
  `protocol/socks/handshake.go:222/228`; affects sing‑box inbounds) and by
  `go-gost/gosocks5`'s `ReadRequest` (reads up to 262 bytes, drops what follows
  the request — `socks5.go:519`; affects GOST). `armon`, `things-go`,
  `txthinking`, `wzshiming`, `haxii`, `getlantern` pass.
- **Clients:** only Outline is L1 (3 RTT incl. TCP vs 4 no‑auth / 5 user/pass for
  the rest); none sends early data. A reference L1+L2 client takes 2.
- **Client pitfalls found:** `gosocks5` `ReadReply` over‑reads and drops tunnel
  bytes and panics on >255‑byte username/domain; `sing` panics on ≥256‑byte
  username; `x/net` returns `i/o timeout` instead of `context.Canceled` on cancel
  and its wrapper conn hides `CloseWrite`/splice; `wzshiming` ignores cancel
  without a deadline; Outline and `gosocks5` bound only the TCP connect with
  `ctx`; `txthinking` drops auth if the password is empty.

## Decision guide

```
Need a SOCKS5 SERVER?
├─ Need UDP?
│  ├─ Yes → things-go/go-socks5 (maintained) ... or wzshiming/socks5 (also a client)
│  └─ No  → things-go/go-socks5 (armon is the same design but unmaintained)
└─ Building a proxy platform / want max throughput → sagernet/sing (GPL‑3.0)

Need a SOCKS5 CLIENT?
├─ TCP only, minimal deps → golang.org/x/net/proxy
├─ Need UDP ASSOCIATE?
│  ├─ Standalone, proven → txthinking/socks5
│  ├─ Standalone, zero-dep, context → wzshiming/socks5
│  └─ Best-tested, OK with SDK dep → Outline SDK transport/socks5

Need to build your own SOCKS5 behavior on raw primitives?
└─ go-gost/gosocks5 (zero-dep RFC codecs + handshake)
```

## Sources

Each library was profiled from GitHub, pkg.go.dev and source, then re‑verified
(stars, importers, releases, UDP, scope, deps). At the snapshot `x/net` was v0.56.0
(v0.59.0 by 2026‑10‑04); Outline shows ~29 open issues (the API's 87 includes PRs).

- https://pkg.go.dev/golang.org/x/net/proxy · https://github.com/golang/net · https://github.com/golang/go/issues/32790
- https://github.com/armon/go-socks5
- https://github.com/things-go/go-socks5
- https://github.com/txthinking/socks5
- https://github.com/go-gost/gosocks5
- https://github.com/wzshiming/socks5
- https://github.com/haxii/socks5
- https://github.com/getlantern/go-socks5
- https://github.com/SagerNet/sing · https://github.com/SagerNet/sing-box
- https://github.com/OutlineFoundation/outline-sdk (formerly Jigsaw‑Code)
- https://github.com/shadowsocks/go-shadowsocks2
