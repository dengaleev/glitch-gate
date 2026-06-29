# Go SOCKS5 Libraries — Comparison

A survey and head‑to‑head comparison of the most popular Go SOCKS5 libraries,
focused on the things that actually matter when picking one: **popularity /
adoption**, **maintenance**, **features (especially UDP `ASSOCIATE`)**, **code
quality & design**, and **performance**.

> **Why this document exists.** This repo's [`go/socks5-udp-test`](../socks5-udp-test)
> tunnels NTP (a UDP protocol) through a SOCKS5 proxy using
> [`github.com/txthinking/socks5`](https://github.com/txthinking/socks5). UDP
> `ASSOCIATE` support is the single most differentiating feature across Go SOCKS5
> libraries — most don't have it — so it gets extra attention below.

**Snapshot date:** 2026‑06‑28. Star counts, `imported by` numbers, and release
dates drift; treat them as a point‑in‑time snapshot. Figures were gathered from
GitHub and pkg.go.dev and independently re‑verified (see
[Methodology](#methodology--sources)).

---

## TL;DR / recommendations

| If you need… | Use | Why |
| --- | --- | --- |
| A **client only**, TCP `CONNECT`, no extra deps | **`golang.org/x/net/proxy`** | Go‑team maintained, idiomatic, stdlib‑only, `context` support. **No UDP.** |
| A **server only**, modern & maintained | **`things-go/go-socks5`** | Active fork of `armon`; built‑in server‑side UDP relay, middleware, `context`. |
| **Client + server, with UDP**, zero dependencies | **`wzshiming/socks5`** | Both sides do `CONNECT`/`BIND`/`UDP`, `context`‑aware, stdlib‑only, clean API. |
| **Client + server, with UDP**, battle‑tested | **`txthinking/socks5`** | Powers Brook/Hysteria; strong real‑world UDP. Dated API, 3 deps, no `context`. |
| **Low‑level protocol primitives** to build your own | **`go-gost/gosocks5`** | Zero‑dep RFC 1928/1929 codecs + handshake; UDP is primitives only. |
| Embedding in a **large proxy platform** | **`sagernet/sing`** / **Outline SDK** | Toolkit‑grade, high‑throughput, full UDP — but heavy and opinionated. |

**For this repo's UDP‑over‑SOCKS5 use case:** `txthinking/socks5` (the current
choice) is a sound, proven option. If you ever want to drop the three external
dependencies and gain `context.Context` support, **`wzshiming/socks5`** is the
closest modern, zero‑dependency alternative with client‑side UDP. For a
client‑only, very well‑tested UDP `ASSOCIATE` dialer, **Outline SDK's
`transport/socks5`** is also worth a look.

---

## Comparison criteria

1. **Popularity / adoption** — GitHub stars & forks, pkg.go.dev "imported by"
   count, and *who actually uses it* in production. Stars measure attention;
   `imported by` and notable dependents measure real adoption.
2. **Maintenance** — last release/commit, open issues, and whether the project
   is alive, in maintenance‑mode, or effectively abandoned.
3. **Features** — the capability matrix: client vs. server, **UDP `ASSOCIATE`**,
   `BIND`, SOCKS4/4a, auth methods (no‑auth / user‑pass / GSSAPI), address types
   (IPv4 / IPv6 / domain), `context.Context`, custom dialer/resolver injection,
   and rules/ACL/middleware hooks.
4. **Code quality & design** — dependency footprint, API ergonomics, test
   coverage, how idiomatic the Go is, and the overall design (turnkey
   client/server vs. low‑level protocol primitives; standalone vs. part of a
   toolkit).
5. **Performance** — published benchmarks (rare), buffer‑reuse strategy
   (`sync.Pool`), and the data‑plane copy/allocation model.

---

## The libraries at a glance

The three the request specifically called out are marked ⭐.

| Library | Role | Standalone? | One‑line take |
| --- | --- | --- | --- |
| ⭐ `golang.org/x/net/proxy` (+`internal/socks`) | Client | Yes (stdlib‑adjacent) | The semi‑official "SOCKS5 from `net`". Clean client, **no UDP, no server**. |
| `armon/go-socks5` | Server | Yes | The classic server lib. **Unmaintained since 2016**, `CONNECT`‑only. |
| `things-go/go-socks5` | Server | Yes | Maintained successor to `armon`; **server‑side UDP**, middleware. |
| ⭐ `txthinking/socks5` | Client + Server | Yes | Full **UDP both sides**, powers Brook/Hysteria. Dated API. |
| ⭐ `go-gost/gosocks5` | Primitives (+thin C/S) | Yes (zero‑dep) | RFC codecs + handshake; the foundation under GOST. **UDP = primitives only.** |
| `wzshiming/socks5` | Client + Server | Yes (zero‑dep) | Unusually complete: `CONNECT`/`BIND`/**UDP** both sides, `context`. |
| `haxii/socks5` | Server | Yes | `armon` fork that adds server UDP. **Dead since 2019.** |
| `getlantern/go-socks5` | Server | Yes | Thin `armon` fork for Lantern. **Dead since 2017, no UDP.** |
| `sagernet/sing` `/protocol/socks` | Client + Server | No (toolkit) | sing‑box's SOCKS engine. SOCKS4/5, **UDP both sides**, heavy abstractions. |
| Outline SDK `transport/socks5` | Client | No (toolkit) | Jigsaw/Outline. Clean **client UDP `ASSOCIATE`**, well‑tested, pre‑1.0. |
| `go-shadowsocks2/socks` | Server handshake + addr parsing | No (toolkit) | ~200‑line building block. No‑auth only, partial UDP. |

---

## Popularity & maintenance

| Library | Stars | Forks | `imported by` | Latest release / last commit | Status |
| --- | ---: | ---: | ---: | --- | --- |
| `golang.org/x/net/proxy` | ~3,000¹ | ~1,300¹ | **4,740** | `x/net` v0.56.0 (2026‑06‑09); actively maintained | ✅ Active (Go team) |
| `armon/go-socks5` | 2,100 | 551 | 423 | last commit 2016‑09‑02; no tags | ⛔ Unmaintained |
| `things-go/go-socks5` | 597 | 100 | 107 | v0.1.1 (2026‑03‑25) | ✅ Active |
| `txthinking/socks5` | 782 | 133 | 181 | last commit 2026‑06‑01 (no tags, pseudo‑versions) | ✅ Active (low‑volume) |
| `go-gost/gosocks5` | 25 | 19 | 68 | v0.5.0; last commit 2026‑05‑21 | ✅ Active (GOST core) |
| `wzshiming/socks5` | 131 | 31 | 21 | v0.7.0 (2026‑01‑12); last commit 2026‑06‑01 | ✅ Active (solo) |
| `haxii/socks5` | 50 | 22 | 7 | v1.0.0 (2019‑07‑08) | ⛔ Dormant |
| `getlantern/go-socks5` | 13 | 4 | 6 | last commit 2017‑11‑14; no tags | ⛔ Dead |
| `sagernet/sing` (socks pkg) | 125² | 96² | 39 | v0.8.11; last commit 2026‑06‑25 | ✅ Active |
| Outline SDK `transport/socks5` | 646³ | 180³ | ~0–2⁴ | v0.1.0‑rc1 / v0.0.23; repo push 2026‑06‑23 | ✅ Active (pre‑1.0) |
| `go-shadowsocks2/socks` | ~4,700³ | 1,488³ | 104 | v0.1.5 (2021‑04‑21); last commit 2024‑10‑20 | 🟡 Maintenance‑mode |

¹ The whole `golang/net` subrepo (the SOCKS5 code is a tiny slice of it); the
**4,740** importers figure is for the `proxy` package specifically.
² `SagerNet/sing` itself (the module containing the SOCKS code). Its headline
dependent **sing‑box has ~35,400 stars** — by deployment this is the
most‑used SOCKS5 code in Go, but the reusable library is `sing`, not sing‑box.
³ Stars/forks are for the *parent* repo; the SOCKS5 code is one subpackage.
⁴ External adoption of just `transport/socks5` is negligible; its reach comes
from being part of the Outline SDK. The module path also recently migrated to
the vanity URL `golang.getoutline.org/sdk` (org renamed Jigsaw‑Code →
OutlineFoundation; the old GitHub path still redirects).

**Notable production users**

- **`x/net/proxy`** — Tor pluggable transports, Psiphon, whatsmeow, ProjectDiscovery (nuclei/naabu), Google Cloud SQL/AlloyDB connectors, Elastic Beats, HashiCorp Packer.
- **`armon/go-socks5`** — frp, chisel, OONI probe, OpenShift HyperShift, Merlin C2.
- **`things-go/go-socks5`** — Sliver C2, Caddy‑L4, NetBird, ProjectDiscovery proxify.
- **`txthinking/socks5`** — **Brook** (author's own), **Hysteria**, Trojan‑Go, RouteDNS, Tor Snowflake.
- **`go-gost/gosocks5`** — **GOST** (`go-gost/gost`, `go-gost/x`), suo5.
- **`wzshiming/socks5`** — Alibaba kt‑connect, enetx/surf, the author's bridge/anyproxy.
- **`sagernet/sing`** — **sing‑box** and its many forks, NekoBox.
- **`go-shadowsocks2/socks`** — Outline SS server, Outline SDK, tun2socks, Clash forks.

---

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

⁵ A `BIND` command constant exists in the source but is not usable through the
public API.
⁶ Per‑client dialer hooks were added in mid‑2026 (PR #28).
⁷ `go-gost/gosocks5` ships *thin* client/server helpers: the server handles
`CONNECT` and `BIND` out of the box; the client does the method handshake and
leaves you to write the `Request`/read the `Reply`.
⁸ `wzshiming/socks5` supports SOCKS5 **and SOCKS5h** (proxy‑side DNS), not SOCKS4.

All eleven support IPv4, IPv6, and domain‑name address types (except where the
whole protocol path is absent). **None implement GSSAPI** — every one supports
only no‑auth and (where applicable) RFC 1929 username/password.

---

## The big differentiator: UDP `ASSOCIATE`

Most Go SOCKS5 libraries are TCP‑`CONNECT`‑only. Here's the real UDP story:

| Tier | Libraries | Notes |
| --- | --- | --- |
| **Full UDP, both client & server** | `txthinking/socks5`, `wzshiming/socks5`, `sagernet/sing` | Production‑grade relays on both sides. |
| **Client‑side UDP only** | Outline SDK `transport/socks5` | Clean `PacketListener`; 16 KiB cap, no fragmentation. |
| **Server‑side UDP only** | `things-go/go-socks5`, `haxii/socks5` | Built‑in server relay (no client). |
| **Primitives only (DIY relay)** | `go-gost/gosocks5`, `go-shadowsocks2/socks` | Datagram encode/decode exists; you wire the relay. |
| **No UDP at all** | `x/net/proxy`, `armon/go-socks5`, `getlantern/go-socks5` | `CONNECT`‑only. |

Detail worth knowing:

- **`txthinking/socks5`** — the strongest *standalone* both‑sides UDP story, and
  the one proven in the wild (Brook, Hysteria). Server tracks UDP associations
  in an in‑memory cache (`patrickmn/go-cache`) keyed by client address, with a
  `LimitUDP` flag that restricts UDP to clients holding an active TCP
  association. This is what makes the [`socks5-udp-test`](../socks5-udp-test)
  NTP example work.
- **`wzshiming/socks5`** — both sides, with two server modes (single‑connection
  vs. separate outgoing connections via `ProxyOutgoingListenPacket`) and a
  `netip`‑based fast path. `context`‑aware and zero‑dependency — the most
  modern standalone both‑sides UDP option.
- **`sagernet/sing`** — full both‑sides UDP with pooled, zero‑copy buffers and
  vectorised packet I/O, but only as part of the sing toolkit.
- **Outline SDK** — client‑only `UDP ASSOCIATE` via `EnablePacket` +
  `ListenPacket`; rejects fragmented datagrams and caps packets at 16 KiB.
- **`x/net/proxy`** — UDP has been an open Go proposal for years
  ([golang/go#32790](https://github.com/golang/go/issues/32790)), now **closed/
  frozen and still unimplemented**. If you need UDP, you cannot use the stdlib
  path.

---

## Per‑library notes

### ⭐ `golang.org/x/net/proxy` — "SOCKS5 from `net`"
The closest thing to a standard‑library SOCKS5: maintained by the Go team, built
on the unexported `golang.org/x/net/internal/socks` engine. Exposes
`SOCKS5()`, `FromURL()`, `FromEnvironment()`, the `Dialer`/`ContextDialer`
interfaces, and `PerHost` routing. **Client‑only, `CONNECT`‑only, TCP‑only.**
No‑auth + user/pass, IPv4/IPv6/domain, full `context`, pluggable forward dialer
for proxy chaining. Tiny (the core engine is ~300 LOC), stdlib‑only, highly
idiomatic, and trivially plugged into `http.Transport`. Pick it when a clean
SOCKS5 TCP dialer is all you need.

### `armon/go-socks5`
The original and most‑imported Go SOCKS5 **server**. Turnkey `New(*Config)` →
`ListenAndServe`, with pluggable `Authenticator`, `CredentialStore`,
`NameResolver`, `RuleSet`, and `AddressRewriter`. Only `CONNECT` actually works
— `BIND` and `ASSOCIATE` are TODO stubs that reply "command not supported."
**Effectively unmaintained since 2016** (no `go.mod`, no tags, still imports the
legacy `x/net/context`). For new server code, prefer the `things-go` fork.

### `things-go/go-socks5`
The de‑facto maintained successor to `armon` (predecessor path:
`thinkgos/go-socks5`). Same clean lineage, modernised with functional options
(`NewServer(opts...)`), `context`‑aware handlers, per‑command middleware,
injectable goroutine pool and buffer pool, and — crucially — a **built‑in
server‑side UDP `ASSOCIATE` relay** with pooled buffers. Server‑only (no
client). `BIND` is a replaceable hook (default: not supported). Lightweight
(only `x/net` at runtime), well‑tested with `testify`. The best "modern
`armon`" if you need a SOCKS5 *server*.

### ⭐ `txthinking/socks5`
Small, KISS‑style library providing **both client and server with genuinely
strong, battle‑tested UDP** — its defining feature and the reason it underpins
Brook, Hysteria, Trojan‑Go and Tor's Snowflake. Returns plain `net.Conn` from
`Dial`, exposes raw wire primitives (`Negotiation`/`Request`/`Reply`/`Datagram`),
and ships a turnkey `DefaultHandle` server. Trade‑offs: **no `context.Context`**,
integer‑second positional timeouts, a blunt positional constructor, partial
`BIND`, no SOCKS4/GSSAPI, and three non‑stdlib deps (`miekg/dns`,
`patrickmn/go-cache`, `txthinking/runnergroup`). Test coverage is light and
there are no benchmarks, but heavy production use is reassuring. *(This repo's
`socks5-udp-test` uses exactly this: `socks5.NewClient(addr, user, pass,
tcpTimeout, udpTimeout)` then `Dial("udp", …)`.)*

### ⭐ `go-gost/gosocks5`
A **zero‑dependency, low‑level protocol library** — the wire foundation under
GOST. Its real value is the RFC 1928/1929 codecs (`Request`, `Reply`, `Addr`,
`UDPHeader`/`UDPDatagram`, `UserPass*`) and the `Selector`‑based handshake
`Conn`. The bundled `client`/`server` packages are thin: the server does
`CONNECT` and `BIND`; **UDP is primitives only** (the server's `CmdUdp` case is
commented out — GOST builds its own UDP relay on top). Recently and actively
tuned (May 2026: allocation reductions, `sync.Pool` buffers, benchmarks, and
several security fixes). Low stars (~25) but heavily used inside the GOST
ecosystem. Choose it when you want to build your own SOCKS5 behavior on solid,
dependency‑free primitives.

### `wzshiming/socks5`
A compact, **zero‑dependency** library with unusually complete protocol
coverage: **`CONNECT`, `BIND`, and `UDP ASSOCIATE` all work on both client and
server**, with full `context.Context` and extensive injectable hooks
(`ProxyDial`, `ProxyListen`, `ProxyListenPacket`, `Resolver`, `BytesPool`,
`Logger`). Client `Dialer` mirrors `x/net/proxy` semantics; server uses the
familiar `ListenAndServe`/`Serve`/`ServeConn`. SOCKS5/SOCKS5h only (no SOCKS4),
no GSSAPI, and access control is limited to an auth callback rather than a full
ACL engine. Idiomatic, ships a CLI, actively (if quietly) maintained by one
author. The strongest **modern, zero‑dep, client+server, UDP‑capable** option.

### `haxii/socks5`
An `armon` fork whose one contribution is **server‑side UDP `ASSOCIATE`** (with
`sync.Pool` buffer reuse). Inherits the clean `armon` config/interfaces; adds no
`BIND`, no client, no SOCKS4. Known gaps: no UDP fragmentation, the UDP relay
**accepts packets without authenticating the sender** (flagged in its own code),
and the UDP path has no tests. **Dormant since 2019** and low adoption — treat as
a historical/minor option.

### `getlantern/go-socks5`
A thin Lantern fork of `armon` that exists mainly to serve Lantern's own
flashlight proxy. Adds only a `context`‑aware `Dial` signature and swaps in
`getlantern/golog`/`netx` (which couples you to the Lantern ecosystem). **No UDP,
no `BIND`, dead since 2017.** No reason to choose it over `armon` or `things-go`.

### `sagernet/sing` (`/protocol/socks`)
The SOCKS4/4a/5 engine inside the **sing** networking toolkit and the actual
SOCKS backbone of **sing‑box** (~35k stars). Full client + server, **UDP both
sides**, client‑side `BIND`, SOCKS4, `context` everywhere, pooled zero‑copy
buffers, and a handler‑callback ("Ex") server API. The catch: it is **not a
standalone drop‑in** — you adopt sing's abstractions (`M.Socksaddr`, `N.Dialer`,
`buf.Buffer`, `HandlerEx`, `Authenticator`) and pull in the whole `common/*`
base, there are no in‑package unit tests, and there's no rules layer (that lives
in the consuming app). Great if you're building a sing‑style platform; overkill
otherwise.

### Outline SDK `transport/socks5`
A clean, idiomatic, **client‑only** SOCKS5 transport from Jigsaw/Outline:
`StreamDialer` (TCP `CONNECT`) + `PacketListener` (**client UDP `ASSOCIATE`**),
no‑auth + user/pass, IPv4/IPv6/domain, `context`, and a single‑write handshake
that saves a round trip. Modern Go (`net/netip`, `errors.Join`), Apache‑2.0,
genuinely well‑tested with `testify`. Limitations: no server, no `BIND`/SOCKS4/
GSSAPI, UDP fragmentation unsupported, 16 KiB packet cap, pre‑1.0, and it's one
package of a larger SDK (depends on the sibling `transport` package). The
best‑engineered *client* UDP option if you're comfortable with the SDK
dependency and its module‑path migration to `golang.getoutline.org/sdk`.

### `go-shadowsocks2/socks`
A ~200‑line, stdlib‑only **building block**, not a library: RFC 1928 address
parsing (`ParseAddr`/`ReadAddr`/`SplitAddr`/`Addr`, `MaxAddrLen = 259`) and a
single server‑side `Handshake` that supports **only no‑auth**, `CONNECT` plus
flag‑gated UDP (`UDPEnabled`), no `BIND`/SOCKS4/user‑pass/`context`. It's an
internal piece of the go‑shadowsocks2 proxy that other projects import
opportunistically for its `Addr` parsing. Stale (last tag 2021). Mentioned for
completeness; not a general‑purpose choice.

---

## Code quality & design

- **Dependency footprint** — `wzshiming/socks5`, `go-gost/gosocks5`,
  `haxii/socks5`, and `go-shadowsocks2/socks` are **zero external deps**.
  `x/net/proxy` is stdlib + its own `internal/socks`. `armon`/`things-go` pull
  only `golang.org/x/net`. `txthinking/socks5` carries three (`miekg/dns`,
  `go-cache`, `runnergroup`). `sing` and Outline drag in their respective
  toolkits.
- **API style** — idiomatic `Dialer`/`ListenAndServe` shapes:
  `x/net/proxy`, `wzshiming`, `things-go`, `armon`. Low‑level/positional or
  protocol‑first: `txthinking` (positional ints, no `context`), `go-gost`
  (manual request/reply on the client). Toolkit‑opinionated: `sing` (handler
  callbacks, single‑letter aliases), Outline (SDK endpoint/dialer types).
- **`context.Context`** — first‑class in `x/net/proxy`, `things-go`,
  `wzshiming`, `sing`, Outline, and (server handlers) `armon`. **Absent in
  `txthinking/socks5`** and `go-shadowsocks2/socks`; partial in `go-gost`
  (client dial only) and the dead forks.
- **Tests** — best: Outline (per‑file suites), `go-gost` (recently expanded
  edge/bench tests), `things-go`, `armon`. Light: `txthinking`, `wzshiming`,
  `haxii` (no UDP tests). None in‑package: `sing` (covered via sing‑box
  integration). Effectively none: `go-shadowsocks2/socks`.
- **Turnkey vs. primitives** — turnkey servers: `armon`, `things-go`, `haxii`,
  `getlantern`, `txthinking` (`DefaultHandle`). Primitive‑first: `go-gost`,
  `go-shadowsocks2/socks`, and `x/net/internal/socks`. Both/hybrid:
  `txthinking`, `wzshiming`.

## Performance

Hard numbers are scarce — almost nobody publishes SOCKS5 benchmarks — so this is
mostly about the data‑plane design:

- **`go-gost/gosocks5`** is the only one shipping **in‑repo benchmarks**
  (`b.ReportAllocs()`), uses `sync.Pool` (513‑byte encode buffers, 1500‑byte
  MTU‑sized relay buffers via `io.CopyBuffer`), and had an explicit May‑2026
  "reduce allocations" pass. The most deliberately perf‑tuned of the bunch.
- **`sagernet/sing`** is built for sing‑box throughput: `sync.Pool`‑backed,
  zero‑copy `buf.Buffer` with header‑extend writes, vectorised packet I/O, and a
  `LazyConn` that defers the success reply. No public numbers, but the design is
  the most performance‑oriented.
- **`things-go/go-socks5`**, **`haxii/socks5`**, and **Outline** use buffer
  pools (`sync.Pool`/`slicepool`) on their relay/UDP paths.
- **`armon`/`getlantern`** use plain `io.Copy` (Go's default 32 KiB buffer, no
  pooling). **`x/net/proxy`** has no relay loop at all — it negotiates `CONNECT`
  and hands back a raw `net.Conn`, so steady‑state cost is zero added copies.
- **`txthinking/socks5`** has **no buffer pooling**; its UDP path does
  per‑datagram header wrap/unwrap and per‑exchange `go-cache` map operations
  with a goroutine‑per‑relay model. Adequate in practice (Brook/Hysteria scale
  on it) but not micro‑optimised.

---

## Handshake pipelining (a client latency optimization)

The RFC 1928 / RFC 1929 client handshake is normally a sequence of
request→response round trips:

```
client → greeting (VER, NMETHODS, METHODS)
client ← method selection (VER, METHOD)              # round trip 1
[ if user/pass ]
client → auth (VER, ULEN, UNAME, PLEN, PASSWD)
client ← auth status (VER, STATUS)                   # round trip 2
client → request (VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT)
client ← reply (VER, REP, RSV, ATYP, BND.ADDR, BND.PORT)   # round trip 3
```

That's **2 round trips (no‑auth) or 3 (user/pass)** before the tunnel is usable —
painful on high‑latency links, and proxies are frequently high‑latency.

**The pipelining opportunity.** When the client commits to **exactly one auth
method up front** — i.e. it *already knows which authorization it will use* — the
server's method‑selection reply is fully predictable. The client can then write
the greeting + (optional auth sub‑negotiation) + the request **back‑to‑back
without waiting for each reply** (ideally coalesced into one `Write`), then read
the 2–3 replies in order. This collapses the handshake to **one round trip**. If
a misbehaving server rejects the method/auth, the eagerly‑sent bytes are simply
discarded when the connection closes — so it's safe, provided the client still
validates each reply.

**Two preconditions hold for *every* Go client surveyed**, so they don't
differentiate:

1. **Replies are read with `io.ReadFull` on the raw `net.Conn`** (no
   `bufio.Reader` read‑ahead, nothing flushed/discarded between phases) — so
   reading a batched set of replies in order Just Works.
2. **The `CONNECT`/`UDP` request bytes never depend on a handshake reply** (they
   come from the destination, known up front) — so they can be written early.

So the deciding factor is purely **how many auth methods the greeting
advertises** — exactly the "when we exactly know about authorization" condition.

### Which client can be extended?

| Client | Advertises auth methods | Already pipelined? | Extend to pipeline | Why |
| --- | --- | :-: | --- | --- |
| **Outline SDK** `transport/socks5` | single (always) | ✅ **yes** | already done | **Reference impl**: assembles greeting+auth+request in one buffer, one `Write`, then ordered `io.ReadFull`. 1 RTT. |
| **`sagernet/sing`** socks | single (always) | ❌ | **easy** | `ClientHandshake5` already advertises one method (`[]byte{method}`); just an additive variant that concatenates the writes. |
| **`txthinking/socks5`** | single (always) | ❌ | **moderate** | Structurally ~90% there; only obstacle is that writes are split across the public `Negotiate()` + `Request()` methods. Add a new method (no breaking change). |
| **`go-gost/gosocks5`** | single (default selector); configurable | ❌ | moderate | Default selector offers one method, but the request write is *caller‑side* and auth is fused inside `Selector.OnSelected` — needs an API path change. |
| **`wzshiming/socks5`** | single (no‑auth) / **two (user/pass)** | ❌ | moderate | Clean injectable design, but the user/pass path advertises **both** `0x00`+`0x02`; must commit to a single method to pipeline that path. No‑auth path is already pipelinable. |
| **`golang.org/x/net/proxy`** | **two (user/pass via public API)** | ❌ | hard | `proxy.SOCKS5()` advertises **both** no‑auth and user/pass whenever auth is set, so auth can't be pipelined without a behavior change — in a *frozen, internal* package. Only the no‑auth path is naturally pipelinable. |

> Server‑only libraries (`armon`, `things-go`, `haxii`, `getlantern`) and the
> client‑less `go-shadowsocks2/socks` have no client handshake to optimize. They
> *interoperate* with a handshake‑pipelining client fine: each reads the
> greeting / auth / CONNECT messages with exact‑length reads, so a coalesced
> handshake is consumed correctly.
>
> **Early *data* pipelining is stricter** (see
> [`../socks5-0rtt-pipelining`](../socks5-0rtt-pipelining)): appending the first
> application bytes to the CONNECT also requires the *server* not to over‑read the
> request into a throwaway buffer, nor to parse via `bufio` and relay from the raw
> conn. Source‑verified, **`go-gost/gosocks5`** (over‑reads the CONNECT with
> `readAtLeast(b[:262], 5)` and discards the tail) and **`sagernet/sing`** (parses
> via `bufio` but relays from the bare conn) are **not** early‑data‑safe; the
> others surveyed are. The interop matrix in that directory is the authoritative
> list.

**Best candidates:** the three that **always advertise a single method** —
`sing` (easiest), `txthinking` (best ROI here, see below), and Outline (already
done). `wzshiming` and `x/net/proxy` need a single‑method *behavior change* on
the user/pass path first, and `x/net` is additionally policy‑frozen.

### Sketch: adding it to `txthinking/socks5` (this repo's lib)

`txthinking` always sets one method (`MethodNone`, or `MethodUsernamePassword`
when creds are present), reads every reply via `io.ReadFull`, and builds the
`CONNECT` request from `dst` *before* `Negotiate` runs. Today `Dial` does:

```go
c.Negotiate(laddr)                       // write greeting → read; [write auth → read]
c.Request(NewRequest(CmdConnect, a,h,p)) // write request → read
```

A pipelined variant (new method, no API break) would:

```go
// 1. dial proxy; pick the single method m (MethodNone | MethodUsernamePassword)
// 2. assemble all outbound bytes up front:
buf := NewNegotiationRequest([]byte{m}).bytes()        // 05 01 m
if m == MethodUsernamePassword {
    buf = append(buf, NewUserPassNegotiationRequest(u, p).bytes()...)
}
buf = append(buf, NewRequest(CmdConnect, a, h, p).bytes()...)
c.TCPConn.Write(buf)                                   // ONE write (1 RTT)
// 3. read replies in order, validating each:
//    NewNegotiationReplyFrom  → rp.Method == m
//    [NewUserPassNegotiationReplyFrom → Status == success]
//    NewReplyFrom             → Rep == success   (and rp.Address() for UDP)
```

The only plumbing missing is `Bytes()` accessors on the request types (or just
reuse the same `append(...)` assembly their `WriteTo` methods already do).
Keep it conditional on "single method advertised" so any future multi‑method
support falls back to the sequential path.

---

## Decision guide

```
Need a SOCKS5 SERVER?
├─ Need UDP?
│  ├─ Yes → things-go/go-socks5 (maintained) ... or wzshiming/socks5 (also a client)
│  └─ No  → things-go/go-socks5 (armon is the same design but unmaintained)
└─ Building a proxy platform / want max throughput → sagernet/sing

Need a SOCKS5 CLIENT?
├─ TCP only, minimal deps → golang.org/x/net/proxy
├─ Need UDP ASSOCIATE?
│  ├─ Standalone, proven → txthinking/socks5
│  ├─ Standalone, zero-dep, context → wzshiming/socks5
│  └─ Best-tested, OK with SDK dep → Outline SDK transport/socks5

Need to build your own SOCKS5 behavior on raw primitives?
└─ go-gost/gosocks5 (zero-dep RFC codecs + handshake)
```

### Mapping to this repo (`socks5-udp-test`)

The NTP‑over‑SOCKS5 test needs a **client with UDP `ASSOCIATE`**. The realistic
standalone choices are `txthinking/socks5` (current), `wzshiming/socks5`, and
Outline SDK. The current code is:

```go
socks5Cl, _ := socks5.NewClient(addr, user, pass, tcpTimeout, udpTimeout) // txthinking
conn, _ := socks5Cl.Dial("udp", remoteAddress)
```

`txthinking` is fine and proven here. Were you to migrate for `context` support
and a zero‑dependency tree, `wzshiming/socks5` exposes a `*Dialer` with
`DialContext`/`Dial` returning `net.Conn` that drops in similarly, and Outline's
`PacketListener` is the cleanest if a client‑only UDP dialer is all you need.

---

## Methodology & sources

Each library was profiled by an independent research pass (GitHub repo pages,
pkg.go.dev, and source files) and then **adversarially re‑verified** by a second
pass that re‑checked the error‑prone facts: star counts, `imported by` counts,
maintenance/release status, the UDP `ASSOCIATE` claim, client/server scope, and
dependency lists. Verified corrections folded into this document include: `x/net`
latest is **v0.56.0** and the UDP proposal #32790 is **closed/frozen** (not
open); Outline's repo shows ~**29 open issues** (the API's `87` includes PRs) and
its org/module renamed to **OutlineFoundation** / `golang.getoutline.org/sdk`;
and `go-shadowsocks2`'s `MaxAddrLen` is **259** (not 270). Numbers are a
2026‑06‑28 snapshot and will drift.

Primary sources (non‑exhaustive):

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
