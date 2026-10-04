# socks0: design

The godoc is the API reference. This file records what the code doesn't show: semantics, rationale and
decisions, each stated once. The bench is [`../socks5-zero-rtt-bench`](../socks5-zero-rtt-bench).

## 1. Goals and constraints

- **Client:** the fewest round trips per cold dial against any SOCKS5 server. L1 pipelines the handshake and L2
  adds early data. The API is stdlib-shaped: `tls.Client`, `http.Transport`, `net.Resolver`, `net.Listener`.
- **Server:** cannot lose pipelined or early bytes. It is net/http-shaped and safe by default: no open SSRF, no
  slowloris, no UDP amplification.
- **Constraints:** MIT, stdlib only, `go 1.26`. No globals and no panics on caller or peer input. No logging.
  The server's `ErrorLog` gets only accept errors and recovered panics. Typed errors in `*net.OpError`.
  Cancellation via `context.AfterFunc`, never a goroutine per dial. Trace hooks instead of logs.
- **Goroutines:** the client starts only one watcher per UDP association. The server starts 1 per `Serve`, 1 per
  conn, +1 during `Relay` and +2 per UDP association. Neither uses timer goroutines. `server` imports `socks0`
  (one error vocabulary, one `KindOf`), never the reverse.

## 2. Client

| Mode | Wire | `DialContext` returns | Errors surface |
| --- | --- | --- | --- |
| `ModeSequential` (L0) | one message per round trip | after the reply | `DialContext` |
| `ModePipelined` (L1, zero value) | greeting + auth + request in one write | after the reply | `DialContext` |
| `ModeEarly` (L2) | L1 + the first `Write`'s data in one write | after TCP connect | first `Read`/`HandshakeContext`; sticky |

- **No fallback between modes.** UDP ASSOCIATE, BIND and RESOLVE carry no stream data, so they run L2 as L1 on
  an identical wire, and one L2 Dialer also serves DNS and UDP. For SOCKS4, L0 and L1 send the same bytes.
- **L2 `Read` before the first `Write`:** it sends nothing and waits, with no timer, so read-first clients
  (`http.Transport`) still send early data. Server-first protocols must call `HandshakeContext` or use L1. A
  deadline expiry there is not sticky, since nothing was sent.
- **L2 in-flight state:** "handshake in flight" is published before the underlying `Write`, so `Read` never
  waits for a `Write` to complete.
- **L2 errors:** sticky, timeouts included, as in crypto/tls. Once one is known, past deadlines unblock the
  other calls.
- **Probes and monitoring use L0, never TFO.** L2's dial time is the TCP connect, not the CONNECT. L0's
  per-message hooks separate a dead proxy from a slow target. In L1, a reply timeout after `GotMethod` may also
  be a server that lost the pipelined request.
- **`Dialer` L0/L1:** returns the proxy conn as is (`*net.TCPConn`: splice, half-close), so BND comes only via
  `GotReply`. Deadlines are cleared, including those `ProxyDial` set. The proxy is always dialed with "tcp";
  "tcp4"/"tcp6" pick the family of IP literals and lookups.
- **`Client`/`ClientAddr`:** these never resolve, because in L2 a lookup would sit inside the first `Write`.
- **One engine:** all entry points share one engine, parameterised by command and version. `Request` exposes it
  over any conn.
- **Auth:** exactly one method is offered, and auth is never silently dropped or swapped. `OfferNoAuth` is
  L0-only, because with pipelining the bytes after the greeting depend on the server's choice.
- **L1/L2 credentials:** they go before the proxy says a word, so anything listening at `ProxyAddr` gets them,
  such as a captive portal or a hijacked port. Use TLS or L0 on untrusted networks.
- **Redaction:** `UserPass`, `Config` and `ProxyURL` redact through fmt (every verb) and slog. `LogValue` is
  needed because slog's JSON handler marshals fields. The auth request is zeroed in the buffers once written
  (best effort).
- **Error chain:** `*net.OpError` → `*HandshakeError{Stage, Err}` → cause. `Stage` is the first message not
  fully written (from the byte count) or received. An L1 timeout at `StageReply` therefore proves the proxy is
  alive and the request is pending at it.
- **`ReplyError`:** no `Timeout` method: 06 matches `ETIMEDOUT`, but the proxy answered. 07 matches
  `errors.ErrUnsupported` everywhere, meaning "no UDP/BIND/RESOLVE here". The 03–06 errno matches are not built
  on plan9. It wins over a malformed reply tail.
- **`ProtocolError` hints:** 'H': an HTTP proxy. VER 0: SOCKS4. VER 5 in the auth reply: Tor rejecting the
  username format. VN 5: a SOCKS5-only server.
- **Cancellation:** wraps `ctx.Err()`, not `Cause`. It always wins for the call that owns the ctx. It is checked
  synchronously, again under the lock before success, and after `ProxyDial` in every mode. A conn without
  deadlines is closed instead.
- **Error strings:** stable, with no addresses or passwords. Store `errors.Unwrap(opErr).Error()`.
- **Resolver errors:** a `*net.DNSError` from a `Dialer` used as `Resolver` is copied with its chain cut. So
  `errors.As(&ReplyError)` on a dial error finds the dial's own reply, never the RESOLVE's 04. Rejected: a new
  wrapper type. Rejected: cutting the chain in `LookupNetIP`, whose callers want the REP.
- **`HandshakeTimeout`, zero-alloc default:** with the built-in dial, the default 30 s is a conn deadline
  counted from the connect; the OS bounds the connect itself. An explicit value, or a `ProxyDial` (TLS and
  chains can tarpit), gets a ctx. A Conn's L0/L1 handshake uses a bare `time.AfterFunc`: a conn deadline would
  override the caller's. An L2 `Read` waiting for the first `Write`, and `Accept`, are not handshakes and stay
  unbounded.
- **Trace, reply loop:** the L1/L2 reply loop parses after each `Read(buf[have:need])`. Hooks fire as soon as
  their message is complete. The loop never reads past the reply. Coalesced replies still take one syscall.
  `HandshakeDone` runs if and only if `WroteHandshake` ran. L2 hooks may run concurrently. Chain hops share the
  ctx trace, told apart by `addr`. `Timings` suits only sequential, unchained dials.
- **`Config.Trace`:** covers implicit handshakes, because `tls.Client(socks0.Client(…))` never passes a ctx.
  `tls.Config`'s callbacks are the precedent; a ctx constructor or `Conn.SetTrace` would add API. For per-conn
  hooks, copy the Config.
- **URL resolution:** `socks5://` and `socks4://` resolve locally, as curl does. This is unlike net/http and
  x/net, and it leaks DNS. TLS schemes resolve at the proxy, since privacy is why TLS is used. `socks5s` is not
  a curl scheme. `u.User != nil` means a `UserPass`, even when empty. Linking crypto/tls into `FromURL` is
  accepted. For a custom `tls.Config`, use `ParseProxyURL` plus your own `ProxyDial`.

**UDP ASSOCIATE.**
- **`net.Resolver` integration:** `DialContext("udp", t)` plugs into `net.Resolver{PreferGo: true, Dial:
  d.DialContext}`, which picks packet framing because the conn is a `net.PacketConn`.
- **Relay socket:** dialed after the reply and connected, so the kernel drops other sources. A chained
  `ProxyDial` never implies a chained relay.
- **DST:** 0.0.0.0:0 by default, since the client cannot know its NATed source. The socket is not bound before
  the request: NAT changes the port anyway, and an unconnected socket loses the kernel filter.
- **`AssociateLocalPort`:** opt-in, because port-translating NATs break it and txthinking/socks5's `LimitUDP`
  takes DST literally.
- **BND substitution:** applies to an unspecified BND IP, or to any BND with `RelayUseProxyHost`. The first
  match wins:
  1. an IP-literal `ProxyAddr`;
  2. without `ProxyDial`, the control conn's peer IP. An IPv4 BND over IPv6 takes the name's first IPv4;
  3. the name via `net.DefaultResolver` (`Dialer.Resolver` is for targets), preferring the control conn's IP,
     then BND's family. With `RelayDial` set, the name is passed unresolved.
- **Hostile BND:** scopes run loopback < link-local < private (RFC 1918, CGNAT, ULA) < global. A relay more
  local than the proxy is refused. An unknown proxy IP counts as global, and the proxy's own IP always passes.
- **Datagrams:** FRAG ≠ 0 is dropped: no server sends it, and reassembly is DoS surface. No writev, because
  `net.Buffers.WriteTo` would split the datagram. Path MTU = pmtu − IP − 8 − `wire.UDPHeaderLen`. DF covers only
  the client→proxy hop.
- **Lifetime:** `Close` waits ≤ 1 s for the watcher, because a `Read` that ignores `Close` keeps it. A relay
  `ECONNREFUSED` waits ≤ 50 ms for `Done`, because ICMP from the closed relay can beat the control EOF.
  Keep-alive on the control conn comes from `ProxyDial` (15 s by default).
- **API choices:** `RemoteAddr` is the target, as in `net.UDPConn`. Drops go to a hook, not counters: a nil hook
  costs one branch. `Done`/`Err` let pools watch an association without reading it.

**BIND, SOCKS4, Tor, TFO.**
- **BIND:** `Listen` takes the *expected peer*, and keeps its name for `net.Listener` familiarity. It accepts
  exactly one conn, on the caller's goroutine; there is no `AcceptContext`, so use `context.AfterFunc(ctx,
  ln.Close)`. Peer bytes after reply 2 are never consumed.
- **SOCKS4:** `Version` is a `uint8`, because two values don't earn a type. USERID comes from
  `UserPass.Username`, so `socks4://user@host` works. `wire.Reply.String` stays SOCKS5-only. In BIND, a reply-1
  DSTIP of 0 means the proxy's IP.
- **Tor:** `*Dialer` is a `Resolver` and never uses itself. There is no `TorDialer`: a non-Tor proxy's REP 07
  already says no. Errors are `*net.DNSError`, so `net.Resolver` code keeps working. `IsNotFound` (REP 04) also
  covers transient failures. Lookups use `Config.Auth`, so `IsolateSOCKSAuth` keeps DNS on the streams' circuit.
- **TFO platform:** Linux only (`TCP_FASTOPEN_CONNECT` ≥ 4.11, plus the `net.ipv4.tcp_fastopen` client bit).
  Darwin's `connectx` isn't in `syscall`, x/sys would break stdlib-only, and `ConnectEx` doesn't fit. Elsewhere
  it fails with `KindConfig`, and nothing is sent.
- **TFO write path:** the first write is a plain `Write`; only `EINPROGRESS` with 0 bytes retries through
  `SyscallConn().Write`. That safety net is tested, but Linux 6.8 never took it. Connect returns at once, so
  `ConnectDone(nil)` proves nothing and Happy Eyeballs settles on the first address. L0/L1 errors still come
  from `DialContext`, bounded by ctx, since SYN retries take minutes. With a warm cookie, an L1 dial takes 1 RTT
  and L2 puts the handshake and data in the SYN. Cold dials gain nothing, so benchmarks must state the cookie
  state.
- **TFO replay:** SYN data may be replayed (RFC 7413 §6), which duplicates the CONNECT and the early data. Use
  TFO only for idempotent first flights. It applies to the first hop only.

## 3. Wire

- **Parse contract:** `Parse*(b) (…, n, err)`. On success, `n` is the message length. On `ErrIncomplete`,
  `len(b) < n ≤ message length`. On any other error, `n` is 0. Errors in the bytes present come before
  incompleteness, so an HTTP proxy is caught at byte 1. So `Read*` needs at most 2 exact reads, and the client
  reads method selection + auth reply + 5 reply bytes in one.
- **SOCKS4 NUL-terminated fields:** these ask for one more byte. Asking further ahead would over-read early data
  or deadlock a server that waits for `n`. The server still parses a one-segment request after one read.
  `ReadRequest4` reads byte by byte while it awaits a NUL.
- **Codec shape:** a full codec in both directions, returning multiple values rather than message structs
  (`ParseReply` reads like `utf8.DecodeRune`). Nothing allocates except a name's string. A byte-array `Addr`
  would be about 280 B. `wire` judges no codes: REP ≠ 0, 0xFF, auth status ≠ 0 and unknown CMD are all valid
  results. The zero `Addr` is an error everywhere, so round-trips are exact.
- **Left out on purpose:** `AppendHandshake`, `MustParseAddr`, `Config.Clone` (use `c2 := *c`) and
  `Conn.Handshake()`.

## 4. Server

**The no-loss invariant.** Servers lose early data at the handover, when buffered bytes and the socket part
ways:
- sing parses through a `bufio.Reader`, then hands over the raw conn.
- gosocks5/GOST reads 262 bytes and drops the rest.
- A pipeline that swaps its decoder for a relay handler drops the bytes that arrive in between.

The server enforces seven invariants:
- **I1 One reader:** until `Reply`, only the server reads, into one per-conn buffer. There is no `bufio` and no
  fixed `ReadFull`.
- **I2 Exact consumption:** each message is consumed by its parsed length. Authenticators read only through
  `AuthConn.ReadMessage`.
- **I3 One handover:** `Request` has no conn accessor. `Reply` returns a `*Conn` that carries the leftover, and
  `NetConn()` returns the conn and the leftover together.
- **I4 Leftover first:** every read path yields the leftover first. `Relay` copies through `WriteTo`, so the
  leftover reaches the target before splice.
- **I5 No discard:** except on close after a failure reply, and on a UDP ASSOCIATE control conn.
- **I6:** a FIN seen during the handshake is returned after the leftover.
- **I7:** the method selection and auth status go out in one write, flushed before any blocking read and before
  the handler runs. A pipelined client gets at most 2 segments, and `GotMethod` precedes a slow target dial.

The server does not read the client during the target dial: early data waits under TCP flow control, and the
small reply cannot deadlock. Only the 2 KiB byte buffer is pooled (the largest handshake is 1032 B); `Request`,
`Conn` and `AuthConn` are views of one unpooled per-conn struct. Exposed slices are capacity-limited, late calls
fail (`ErrReplied`, `net.ErrClosed`), a buffer user code has seen goes to the GC rather than the pool, and
released buffers are zeroed.

**Handlers and lifecycle.**
- **Never fake success:** a server-generated reply clamps 00 to 01. This covers a handler that returns without
  replying (`ErrNoReply`), `Allow` denials and recovered panics. Panics are recovered as in net/http, so that
  one bad conn cannot cut every tunnel.
- **Handler ctx:** canceled by `Close` or by `ServeSOCKS` returning, not by a client disconnect. Noticing a
  disconnect would need a read, which I1 forbids. Any cancellation closes the client conn. So a cancelable
  `BaseContext` closes conns, unlike http.Server. `Relay` with the handler's own ctx needs no `AfterFunc`,
  saving 5 allocs.
- **`ConnectHandler.Dial` owns its policy:** `Filter` is not applied, because a half-applied filter (IP literals
  only) gives false confidence. `Dialer` keeps the filter, and `Filter.Control` composes.
- **Upstream L2:** a handler dialing upstream in L2 replies optimistically, so an upstream failure shows up as a
  reset. That is the trade-off for end-to-end zero RTT.
- **CONNECT BND** is the target's local address (RFC); for privacy, use a custom handler. **Timeouts** reply 06,
  which round-trips to the client's `ETIMEDOUT`. 04 stays for DNS.
- **Shutdown:** closes conns still in the handshake. They got no reply, so no target saw their data. A CAS makes
  New→Active fail once Shutdown starts.
- **Lingering close:** after a failure reply, `05 FF` or an auth failure, the server does `CloseWrite`, drains
  up to 64 KiB or 500 ms, then closes. This runs at conn end, not in `Reply`.
- **Auth failures:** an unknown user costs the same as a wrong password. An Authenticator error not matching
  `ErrAuthFailed` closes without a status byte.

**Target policy: SSRF and DNS rebinding.**
- **Connect-time filtering:** `Filter` runs in `ControlContext` for every address tried. The checked IP is the
  connected IP, so names, Happy Eyeballs and rebinding cannot slip past.
- **UDP and RESOLVE** resolve, check and use one IP; their caches never re-resolve. Addresses are unmapped and
  zone-stripped first, and `Filter.Control` fails closed.
- **Own host:** checked before connect against the interface addresses (cached 1 s, with a route lookup as
  fallback), so the host's open and closed ports look alike. After connect, a local IP equal to the remote IP
  gets 02.
- **No loop detection:** it was rejected, because NAT rewrites the source and port collisions would refuse real
  clients. Use `SelfAddrs`.
- **Filter rules:** a Filter must be pure, because UDP caches verdicts. It must not panic, because it runs on
  Happy Eyeballs goroutines.
- **No DNS oracle:** a denied CONNECT to a *name* gets 04, not 02. BIND filters DST before listening.

**Limits and defaults.**

| Knob | Default | Why |
| --- | --- | --- |
| `HandshakeTimeout` | 10 s | absolute from accept to request; also bounds each reply write |
| `MaxHandshakes` | 1024 | deferring the buffer to the first byte was rejected: a read per conn to save ~3 KiB vs an 8 KiB stack |
| `MaxConns` | none | depends on fd limits and memory: set it on a public server |
| `Relayer.UserTimeout` | 2 min | `TCP_USER_TIMEOUT` keeps splice; `IdleTimeout` (off) disables it |
| UDP idle / `MaxDatagram` / `MaxTargets` | 5 min / 4096+262 / 1024 | only relayed datagrams refresh the timer |

- **Not built in:** quotas and rate limits (they cost splice: wrap the target conn), PROXY protocol (wrap the
  listener), a port-25 deny (use `Allow`), a buffer-size knob.
- **Relay:** splice both ways on Linux, where `io.Copy` reaches `(*net.TCPConn).ReadFrom`. Elsewhere, pooled 32
  KiB buffers.

**UDP relay, BIND, SOCKS4, RESOLVE.**
- **UDP client IP and DST:** the client IP is the control conn's peer. DST counts only if its IP is the peer's
  or unspecified, and then its non-zero port is enforced. Any other IP, or a name, means the peer IP, so a
  client cannot aim the relay at a victim.
- **UDP port lock:** otherwise the first valid datagram locks the port. A host that can forge the client's IP
  (no BCP 38), or that shares its CGNAT address, can win that race. Mitigations: a random port and DST.PORT
  (`AssociateLocalPort`). For strong guarantees, use UDP-over-TCP. Behind NAT, set `Advertise`.
- **UDP filtering** defaults to `AddressAndPortDependent` (DNS, NTP and QUIC work); STUN and P2P opt into
  `EndpointIndependent`. A header cache gives 0 allocs for repeat targets. Names are cached 60 s, failures
  included, and each name counts toward `MaxTargets`. Lookups are bounded at 5 s.
- **UDP drops:** FRAG ≠ 0, datagrams that fill the buffer (possibly truncated) and malformed datagrams are
  dropped. No error datagrams are sent, so there is no reflection. Read errors other than `net.ErrClosed` are
  skipped, because Windows reports ICMP there.
- **BIND** checks the peer IP, not the port, because FTP data comes from port 20 or a random port. While
  accepting, it reads the client into the conn's buffer, which detects EOF portably and keeps I1/I3. For
  per-identity limits, use `Allow` + `Trace.Done`.
- **SOCKS4:** off by default. Without `UserID` it needs the built-in `NoAuth`, checked by type, so a custom
  method-00 Authenticator (an IP allowlist) cannot be bypassed.
- **RESOLVE:** F0 answers with the first allowed address. F1 is filtered before `LookupAddr`. The conn closes
  after the reply, as in Tor.
- **Allocations:** handshake + reply take 3 allocs (+1 for a name, +2 for user/pass). A whole CONNECT with
  `Relay` takes 7 on darwin and 9 on Linux. The bench gives 94 against 88–92 for minimal servers. That gap is
  accepted: a cancelable dial ctx arms net's connect interrupter (~5), and `TCP_USER_TIMEOUT` costs two
  `RawConn`s.

## 5. Security model

| Threat | Mitigation |
| --- | --- |
| Open relay | `Auth` nil = no auth (a useful zero value), but `DefaultFilter` still blocks internal targets; `Admit`/`Allow` allowlists |
| SSRF, metadata, own host, loops, rebinding | connect-time `DefaultFilter` on the connected IP (incl. Azure 168.63.129.16), own-host check, `SelfAddrs`, self-connect check |
| Port-scan and DNS oracles | own-host check before connect; 04 for denied names; BIND filters DST first |
| UDP amplification and reflection | source lock, port-dependent filtering, `MaxTargets`, `MaxDatagram`, idle timeout, FRAG dropped, no error datagrams |
| Slowloris and exhaustion | absolute handshake deadline, reply-write deadline, `MaxHandshakes`, `MaxConns`, `Admit`, ≤ 1 KiB auth messages |
| Server credentials | constant-time SHA-256 compare; zeroed buffer (best effort); never in errors, traces or logs; RFC 1929 is cleartext, so use `ServeConn(tls.Server(…))` |
| SOCKS4 auth bypass | off by default; built-in `NoAuth` checked by type |
| Malformed input | fuzzed `wire` at 100% coverage; bounded lengths (client reply ≤ 64 KiB); panics recovered |
| Hostile proxy (client) | BND scope check, `SO_BROADCAST` cleared on the relay, exact reads, `HandshakeTimeout` against tarpits; redaction; L1/L2 on untrusted networks → TLS or L0 |
| Info leaks | CONNECT BND reveals the egress address (RFC); hooks get raw names, so escape control characters |

Accepted security-review fixes, each pinned by a `TestSec_*` regression test:
- **Client:** credential redaction and auth-buffer zeroing; the hostile-BND scope check with `SO_BROADCAST`
  cleared; opt-in `AssociateLocalPort`; the 30 s `HandshakeTimeout` default against tarpits.
- **Server:** SOCKS4 admitted only with the built-in `NoAuth`; `SelfAddrs` (1:1 NAT loops); Azure WireServer in
  `DefaultFilter`; the own-host check before connect (no port-scan oracle); DST.PORT honoured for an unspecified
  DST.ADDR; buffers seen by user code never re-pooled; BIND filters DST before listening; only relayed datagrams
  refresh the UDP idle timer; `MaxHandshakes` 1024 by default; `MaxConns` shared across listeners without
  overshoot or stall; `MaxDatagram` validated and relay panics recovered; accept errors logged quoted;
  `server.UserPass` prints only its user count.

## 6. Decisions log

- **Modes:** explicit, with no fallback; the zero value is L1.
- **Error types:** `HandshakeError` is a wrapper rather than a `Stage` field on each type, and `KindOf` is a
  func rather than methods. Both cover transport and ctx errors.
- **Server packaging:** the server is a subpackage, so client binaries stay small.
- **Safe handover:** `Reply` returns the conn, rather than offering an `http.Hijacker`-style API, so the safe
  path is the only path.
- **Deferred:** server-side TFO, carrying `Request.Early` in the target's SYN. The API is ready for it (`Early`
  and `ConnectHandler.Dialer`).

## 7. Testing and verification

- **Race and leaks:** `-race` on macOS and Linux, plus godoc examples. A cleanup helper asserts that the
  goroutine count returns to baseline.
- **Fuzzing:** `wire` (parse + round-trip), the client entry points and UDP read path, `AuthConn`, the server
  UDP paths and SOCKS4. `FuzzServeConn` feeds arbitrary bytes and splits; the handler must read exactly
  `input[hsLen:]`.
- **Readiness:** `server/readiness_test.go` mirrors the bench matrix: auth × ATYP × early {0, 64 B, 1.5 KiB, 64
  KiB} × 7 splits. It adds early data + `CloseWrite`, a split u/p, a slow dial with 1 MiB early data,
  target-first protocols, and I7.
- **Interop:** `../socks5-zero-rtt-bench/interop_test.go`: 3 modes × 9 servers × auth × ATYP × size. L2 on sing
  and GOST is expected to fail. Every bench client × `socks0/server`: 132 cases. `server/interop_test.go`: the
  socks0 client against the server, TLS included.
- **Splice, security, coverage:** `TestDelegation` (spy conns), `TestSpliceUsed` (`/proc/self/fd`); security
  regressions are `TestSec_*` in `sec_client*_test.go` and `server/sec_*_test.go`. Coverage: wire 100%, client
  ~97%, server ~96%.
- **Linux-only tests** (run from `go/socks0`; the Docker commands are in the file headers):
  - `SEC_NETNS=1 go test -race -run '^TestSec' . ./server` needs `--cap-add NET_ADMIN`. It covers public
    addresses, a 1:1 NAT hairpin and a public subnet (`server/sec_netns_linux_test.go`). `SEC_PRIVATE_IP`
    selects the two-container NAT variant.
  - `SOCKS0_NETEM_RTT=100ms go test -run TestV2TFORoundTrips` needs `tcp_fastopen=3` and netem on lo. With a
    warm cookie it expects 1 RTT for an L2 dial + write + echo, 1 for L1 and 2 for L0. `SOCKS0_NETEM_TC=1` adds
    the deferred-error tests.
