# socks5-0rtt-pipelining

A design study and working reference implementation of **0-RTT data pipelining**
for SOCKS5 CONNECT over [`github.com/txthinking/socks5`](https://github.com/txthinking/socks5).

This is the next layer beyond the *handshake* pipelining benchmarked in
[`../socks5-pipelining-bench`](../socks5-pipelining-bench). Handshake pipelining
coalesces the SOCKS5 greeting + optional auth + CONNECT into a single write to
remove the pre-request round trips, but the application still waits for the
CONNECT reply before sending its first byte. **0-RTT data pipelining** removes
that last wait too: it appends the application's *first payload* (e.g. a TLS
ClientHello) to the very same write and sends it **before any reply is read** —
exactly the way TLS 1.3 early data and TCP Fast Open carry application bytes
before the peer confirms. The proxy forwards that payload to the target the
instant the proxy→target connection opens.

It is a **pure client-side optimization**: no SOCKS5 protocol extension and no
server change. It interoperates with unmodified RFC 1928 servers — including
txthinking's own — and the reference `Conn` here is a drop-in
`http.Transport.DialContext`.

> **Status / scope.** The latency win is real but it is *optimistic* delivery,
> so it is opt-in and only appropriate for a replay-safe first payload (a TLS
> ClientHello being the ideal case). See [Safety & policy](#safety--policy).

---

## The idea

The regular client does the handshake at dial time and only then lets the
application write:

```
Negotiate():  greeting ─►        ◄─ method        (1 RTT)
              [auth ─►           ◄─ auth status]   (1 RTT, user/pass)
Request():    CONNECT ─►         ◄─ reply          (1 RTT)
              ───────────────────────────────────  tunnel ready
app:          first payload ─►   ◄─ response
```

Handshake pipelining collapses the three request→reply exchanges into one round
trip, but the application *still* waits for the surfaced CONNECT reply before it
sends the first payload.

0-RTT data pipelining instead **defers the handshake** and ships it together
with the first payload, validating the replies lazily:

```
app Write(p): [ greeting | [auth] | CONNECT | p ] ─►        one write, no waiting
              proxy ReadFulls greeting/[auth]/CONNECT, dials target,
              and the first relay read forwards p to the target
app Read():   ◄─ [ method | [auth] | reply ] then target response
              (the replies are io.ReadFull-validated in order, then data flows)
```

Because the SOCKS5 reply frame is fixed/length-parseable and the client
advertises exactly one auth method, the reply sequence is fully predictable, so
nothing is lost by reading it after the payload is already on the wire.

---

## RTT accounting

Let **Rcp** = client↔proxy RTT and **Rpt** = proxy↔target RTT. The clean metric
is *when the first application byte reaches the proxy* (measuring at the target
adds the proxy→target connect cost, which every strategy pays equally — see the
caveat below). No-auth, proxy TCP connection already established:

| Strategy | What happens before the first app byte reaches the proxy | First app byte at proxy |
| --- | --- | ---: |
| **Sequential** (RFC 1928) | greeting/method (1 Rcp) + CONNECT/reply (1 Rcp) + send (½ Rcp) | **2.5 Rcp** |
| Sequential, user/pass | + auth exchange (1 Rcp) | 3.5 Rcp |
| **Handshake-pipelined** | coalesced handshake out (½) + replies back (½) + send (½) | **1.5 Rcp** |
| **0-RTT data pipelined** | one flight carrying handshake + payload (½) | **0.5 Rcp** |
| **0-RTT + TCP Fast Open** (warm cookie) | same flight, carried in the SYN | **0.5 Rcp**, and the separate +1 Rcp TCP handshake is gone too |

So, relative to **handshake pipelining, 0-RTT data pipelining saves exactly one
Rcp** — and the round trip it removes is precisely *wait-for-the-CONNECT-reply,
then send*. Relative to sequential it saves **2 Rcp** (no-auth) / **3 Rcp**
(user/pass). Adding TFO additionally removes the proxy TCP-handshake round trip,
so a warm connection reaches *literal* zero added round trips before the first
payload is on the wire — only the irreducible ½ Rcp one-way propagation remains.

**Caveats on the figure** (from adversarial review):

- **Measured at the target, the saving can be masked.** The proxy starts dialing
  the target at the same wall-clock moment in every strategy; 0-RTT only changes
  *when the payload is available at the proxy to forward*. If Rpt (the
  proxy→target connect) is large relative to Rcp, target-observed first-byte
  delivery is dominated by the connect and the 1-Rcp saving overlaps with it.
  The saving is unconditional *at the proxy* and for first-payload *delivery
  latency*; it is not a promise that the target responds 1 Rcp sooner.
- **It does not make the TLS handshake 0-RTT.** Saving 1 Rcp on the ClientHello
  starts the TLS handshake one round trip earlier; ServerHello/Finished still
  cost their Rpt-bound round trips.
- **Server-speaks-first protocols save nothing.** If the application's first
  operation is a Read (SMTP/FTP/SSH banners), there is no first payload to
  pipeline and it degrades to handshake-only pipelining.

### Measured

The in-process test harness (`go test -v`) runs all three strategies against a
**real, unmodified txthinking server** over a simulated 12 ms one-way link
(Rcp ≈ 24 ms):

```
first byte at target (Rcp/2=12ms): sequential=87ms  pipelined=74ms  0-rtt=13ms
reads from proxy before first app byte:  sequential=4  pipelined=4  0-rtt=0
```

The decisive structural signal is the last line: **0-RTT sends application data
having read nothing back from the proxy.** (The wall-clock shim sleeps per
syscall, so it over-counts the multi-read CONNECT reply and inflates the gap;
read the ordering, not the ratio — the precise model is the table above.)

---

## Why it needs no server change

The whole technique rests on one server invariant:

> **The post-CONNECT relay must read the client→target direction from the same
> byte stream that consumed the handshake.**

An RFC 1928 server reads each handshake message and then relays. If it parses
the handshake with `io.ReadFull` of each message's exact length on the raw
connection (no read-ahead) and then relays from that same connection, the early
bytes the client appended after CONNECT simply sit in the kernel receive buffer
through handshake parsing and are delivered to the target by the **first relay
read**, once the proxy→target dial completes. Nothing in RFC 1928 forbids the
client from sending those bytes early; it only says the client *may* start
passing data after a success reply.

### txthinking/socks5 qualifies (verified against source)

- `server_side.go` — `NewNegotiationRequestFrom`, `NewUserPassNegotiationRequestFrom`,
  and `NewRequestFrom` each `io.ReadFull` exactly the message length on the raw
  `*net.TCPConn`. No `bufio`, no over-read.
- `connect.go` — `Request.Connect` only *writes* the reply to the client conn;
  it never reads from it.
- `server.go` — `DefaultHandle.TCPHandle` relays client→target with
  `i, err := c.Read(bf[:]); rc.Write(bf[0:i])` on that same raw `c`
  (server.go ~L287–301).

So appended early data is forwarded by the first `c.Read` after the target dial
returns. **No modification required.** The reference `Conn` here is symmetric on
the client side: it reads each reply with `io.ReadFull` of the exact length on
the *unwrapped* proxy conn, so even if the proxy coalesces its CONNECT reply with
the first target bytes into one TCP segment, the fixed-length read leaves the
target data intact for the next read.

### Early-data interop across Go SOCKS5 servers

The decisive question is **not** whether a server uses `bufio` — it is *where it
relays from*. A `bufio`-wrapped handshake is fine **as long as the relay reads
from that same `bufio.Reader`**. The hazard is the specific combination
*`bufio` for the handshake + relay from the raw conn/fd*, which strands the
buffered early bytes. Every server surveyed is safe; the hazard is a pattern to
watch for in unaudited servers.

| Server | Handshake parse | Relay reads from | Early-data |
| --- | --- | --- | :-: |
| `txthinking/socks5` | raw `io.ReadFull` | same raw conn | ✅ safe |
| `wzshiming/socks5` | raw `readByte`/`readBytes` | same raw conn | ✅ safe |
| `go-gost/gosocks5` | raw `readFull` | same raw conn | ✅ safe |
| `armon/go-socks5` | `bufio.NewReader` | **same** `bufConn` | ✅ safe |
| `things-go/go-socks5` | `bufio.NewReader` | **same** `request.Reader` | ✅ safe |
| Dante / 3proxy / `ssh -D` | exact-length reads | same fd | ✅ safe¹ |
| *hazard pattern* | `bufio` read-ahead | **raw** conn/fd (≠ handshake reader) | ❌ early bytes lost |

¹ Architectural assessment (read each SOCKS message as an exact-length read and
relay from the same socket), not source-quoted here.

Because there is no SOCKS5 capability bit to detect early-data support (unlike
[Tor proposal 181](#prior-art)'s version gate or SOCKS6's Initial Data field),
treat it as best-effort: gate it on a known-good proxy, or be prepared for the
hazard server to drop the first payload.

---

## Client design

The reference implementation (`zerortt.go`) is a deferred-handshake
`net.Conn`. It performs no I/O at dial time; the handshake is buffered and
flushed exactly once, and the replies are validated lazily.

```
Dial ─► (nothing on the wire)
  │
  ├─ first Write(p)  ─► flush: write [handshake | p] in ONE write   (0-RTT path)
  ├─ first Read()    ─► wait ClientDataWait for a concurrent Write to
  │                     coalesce; else flush [handshake] alone        (fallback)
  └─ first Read also ─► io.ReadFull + validate method/[auth]/reply,
                        then surface target bytes
later Write/Read ──► pass through to the raw conn
```

### Edge cases and how they are handled

| Case | Handling |
| --- | --- |
| **`Write` return value** | Reports `len(p)` only — never the prepended handshake bytes. |
| **Read-before-write** (server speaks first) | The first `Read` flushes the handshake alone (no early data) and proceeds — degrading to handshake pipelining. Correctness preserved, 0-RTT benefit forgone. |
| **Concurrent Read/Write** (`http.Transport` runs readLoop + writeLoop) | The first `Read` waits up to `ClientDataWait` (default **10 ms**, à la Outline SDK) for the first `Write` to supply early data before flushing alone, so coalescing is reliable instead of racy. |
| **CONNECT / auth failure** | Surfaced as an error on the first `Read` (the optimistic payload was already sent — see safety). |
| **Reply coalesced with target data** | Replies are read with exact-length `io.ReadFull` on the unwrapped conn, leaving target data for the next read. |
| **Handshake-write failure** | Recorded and propagated to subsequent `Write`/`Read` rather than writing more onto a corrupt control stream. |
| **`Close` before any flush** | The proxy sees a connection opened and closed without a handshake — harmless. |
| **Deadlines** | `SetDeadline`/`SetReadDeadline`/`SetWriteDeadline` pass through to the raw conn; the deferred handshake runs within the caller's first Write/Read deadline. |

`buildHandshake` reuses txthinking's wire primitives (`NewNegotiationRequest`,
`NewUserPassNegotiationRequest`, `NewRequest`) via a `bytes.Buffer`, producing
byte-for-byte what `Negotiate()` + `Request()` would send — just collected into
one buffer.

### Known limitations (honest disclosure)

- **Reply-read timeout is terminal.** If a read deadline fires *during* reply
  validation, the partially-consumed reply cannot be cleanly resumed and the
  cached error makes the conn permanently failed. Prefer to bound the handshake
  with the dial/first-Read deadline, not a short polling deadline.
- **A connection that never reads and never writes never handshakes.** Nothing
  triggers the flush. Acceptable for protocols that eventually do one or the
  other; call `Flush()` to commit the handshake explicitly.
- **Partial-write assumption.** `flush` assumes the proxy conn is all-or-nothing
  on `Write` (true for `*net.TCPConn`). An injected `dialProxy` conn with
  short-write semantics could split the handshake mid-stream.
- **No capability negotiation.** There is no way to detect a hazard server; this
  is best-effort optimistic data.

---

## Safety & policy

0-RTT data pipelining is **optimistic**: the early bytes leave the client before
auth and CONNECT are confirmed. This must be **opt-in** and used only for a
replay-safe first payload — the same discipline TLS 1.3 0-RTT and TCP Fast Open
require, and the application (not the transport) owns the choice of what is safe.

What can go wrong, and why a **TLS ClientHello is the ideal payload**:

- **CONNECT/auth failure or reset** discards the early bytes; the application
  has "sent" data that reached no target, and any transparent retry could
  duplicate it. A ClientHello carries no application semantics and is freely
  re-sendable on a fresh connection; a plaintext HTTP `POST` (or any
  non-idempotent first write) is not. (RFC 8470's lesson for HTTP early data:
  send only *safe* methods; never trust a method label as a proxy for
  idempotency.)
- **A favorable difference from TLS 0-RTT.** TLS early data is replayable
  because it is bound to a resumption PSK and can be re-injected *across*
  connections. A SOCKS5 early-data write over a single TCP connection has **no
  such cross-connection replay primitive of its own** — the bytes are delivered
  once over an established stream. So the SOCKS layer does not itself introduce a
  new replay vector; the residual risk is delivery-before-confirmation plus
  whatever the *application* does on retry.
- **TCP Fast Open does add a genuine replay vector.** SYN data is not protected
  by TCP sequence numbers and can be delivered more than once (RFC 7413 §6.1),
  so combining 0-RTT pipelining with TFO inherits TFO's idempotency requirement.
  Gate TFO separately.

Recommended policy: expose early data as a deliberate choice, default it off,
prefer it for TLS-wrapped tunnels (HTTPS targets), and surface a CONNECT failure
to the caller rather than silently swallowing the lost payload.

---

## Combining with TCP Fast Open for *literal* 0-RTT

The single coalesced write is exactly what TFO needs: hand
`greeting | [auth] | CONNECT | payload` to a TFO dial as the SYN data and the
proxy's `accept()` yields a connection whose first read already contains the full
handshake plus the first payload — same server behavior, just delivered in the
SYN.

- **Go has no stdlib client TFO API** ([golang/go#4842](https://github.com/golang/go/issues/4842)
  is accepted-but-unplanned for the client). The practical library is
  [`github.com/database64128/tfo-go`](https://pkg.go.dev/github.com/database64128/tfo-go/v2),
  whose dial functions take an extra `b []byte` that becomes the SYN data. Splice
  it in via txthinking's `Client.DialTCP` hook (or this package's `dialProxy`
  factory).
- **Warm cookie required.** The first-ever connection to a proxy IP:port has no
  cookie and falls back to a normal handshake (RFC 7413 §4.2.1) — no 0-RTT on
  the cold connection. Benchmarks must distinguish cold from warm.
- **SYN size cap.** Without cached MSS, SYN data is limited to ~536 bytes (IPv4)
  / ~1220 (IPv6). The tiny SOCKS5 handshake (~3–22 B) plus a typical ClientHello
  fits, but a large ClientHello with many extensions can overflow; the remainder
  then follows the handshake normally (still correct).
- **Middleboxes.** ~6 % of paths drop SYNs carrying data; the kernel retransmits
  a dataless SYN, so the early bytes must be tolerated arriving post-handshake
  too. Both ends need TFO enabled at the OS level.

This package does **not** implement TFO; it is documented as the next step and
the design is TFO-ready (one coalesced first write, server-read logic agnostic
to whether bytes arrived in the SYN or the first segment).

---

## Prior art

0-RTT data pipelining is novel *for SOCKS5* but well-precedented in adjacent
proxy protocols:

- **Tor proposal 181 — optimistic data.** The client starts sending data
  immediately after the SOCKS CONNECT, without waiting for the reply (cited
  ~25–50 % latency reduction); requires server-side support and is version-gated.
  The direct conceptual ancestor.
  <https://spec.torproject.org/proposals/181-optimistic-data-client.html>
- **SOCKS6** adds an explicit *Initial Data* field (up to 2¹⁴ bytes sent with the
  request) — created in part *because* SOCKS5 has no early-data field.
  <https://datatracker.ietf.org/doc/html/draft-olteanu-intarea-socks-6-11>
- **Outline SDK.** Its SOCKS5 dialer coalesces greeting+auth+CONNECT into one
  write (the handshake-pipelining half) but does **not** append app data; its
  *Shadowsocks* dialer *does* coalesce the first app write as early data via a
  10 ms `ClientDataWait`/`LazyWrite` — the pattern this package borrows for the
  read/write race.
- **Shadowsocks-2022 (SIP022) / Brook** inline the target address *and* the first
  payload into the first encrypted message by construction — structurally 0-RTT,
  no "tunnel established" reply at all. Brook is by the same author as
  txthinking/socks5.
- **HTTP CONNECT fast-open / RFC 9298 / RFC 9931.** Sending the TLS ClientHello
  before the `200 Connection Established` is the HTTP analog; RFC 9298
  (CONNECT-UDP) explicitly permits datagrams before the 2xx, and RFC 9931 covers
  the security of such optimistic protocol transitions — both warn the data may
  be discarded on failure.
- **TLS 1.3 early data (RFC 8446 §2.3, §8) / RFC 8470 / TCP Fast Open
  (RFC 7413).** The replay/opt-in discipline this design inherits.

---

## This package

| File | What it is |
| --- | --- |
| `zerortt.go` | The deferred-handshake `Conn` and `Dial` — the reference implementation. |
| `lab.go` | Self-contained in-process lab: latency shim, round-trip counter, echo target, an **unmodified** txthinking proxy, and the sequential / handshake-pipelined comparison dialers. |
| `zerortt_test.go` | The proof and demonstration (below). |

### Run it

```sh
go test -v ./...            # correctness + the round-trip / latency demonstration
go test -race ./...         # exercises the concurrent read/write paths
```

What the tests establish, all against a **real, unmodified txthinking server**:

- `TestEarlyDataReachesTargetNoAuth` / `…UserPass` — early data is delivered to
  the target and echoes back; the first payload leaves the client in **one write
  with zero prior reads**; `Write` reports app bytes only.
- `TestConcurrentReadWriteCoalesces` — a `Read` racing ahead of the first `Write`
  (as `http.Transport` does) still coalesces into a single proxy write.
- `TestHTTPThroughZeroRTT` — works as a drop-in `http.Transport.DialContext`.
- `TestServerSpeaksFirstFallback` — read-first protocols degrade gracefully.
- `TestConnectFailureSurfacedOnRead` — the optimism semantics: a failed CONNECT
  surfaces on `Read`.
- `TestLatencyOrdering` / `TestRoundTripEconomy` — the ordering and round-trip
  economy of the three strategies.

### Use it

```go
conn, err := zerortt.Dial(proxyAddr, user, pass, "example.com:443", nil)
// conn is a net.Conn. Its first Write coalesces the SOCKS5 handshake with the
// payload. Wrap it in crypto/tls — the ClientHello becomes the 0-RTT payload:
tlsConn := tls.Client(conn, &tls.Config{ServerName: "example.com"})
```

Or as an `http.Transport`:

```go
tr := &http.Transport{
    DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
        return zerortt.Dial(proxyAddr, user, pass, addr, nil)
    },
}
```

---

## References

- RFC 1928 (SOCKS5) · RFC 1929 (user/pass auth)
- RFC 8446 (TLS 1.3, early data) · RFC 8470 (Using Early Data in HTTP) · RFC 7413 (TCP Fast Open)
- RFC 9298 (Proxying UDP in HTTP) · RFC 9931 (Security of Optimistic Protocol Transitions)
- Tor proposal 181 (optimistic data) · SOCKS6 draft (Initial Data)
- Outline SDK `transport/socks5` & `transport/shadowsocks` · Shadowsocks-2022 (SIP022) · Brook
- [`github.com/txthinking/socks5`](https://github.com/txthinking/socks5) · [`github.com/database64128/tfo-go`](https://github.com/database64128/tfo-go)
