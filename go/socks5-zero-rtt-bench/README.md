# socks5-zero-rtt-bench

How close do Go SOCKS5 libraries get to zero RTT on a cold dial? **L1
(pipelining):** one auth method, greeting + [auth] + CONNECT sent at once: 1
handshake RTT, not 2 (no-auth) / 3 (u/p). **L2 (early data):** payload before the
CONNECT reply too: 0 RTT over TCP. Servers must keep those bytes; clients are
scored by round trips to the first response byte.

## Run

```sh
./run.sh                       # all, in a netem topology (Docker; macOS: colima start)
./run.sh -n 50 -rtts 0,200     # flags go to `bench rtt`
SERVER=socks0/server ./run.sh  # clients' proxy (default: first all-✅ server, armon)
SERVER=armon/go-socks5,socks0/server ./run.sh  # one clients table per proxy
./run.sh check                 # verify the topology: RTTs, MTU, offloads, segmentation
go test ./...                  # harness, library smoke tests, socks0 interop, no Docker
go test -bench . ./...         # allocs/op per server and client
```

## Results

`./run.sh`, colima on Apple Silicon, 2026-10-04:

```
┌───────────────────────────────────────────────────────────────────────────────┐
│ Servers · L1/L2 readiness (in-process)                                        │
├──────────────────────┬────┬─────────┬─────────┬─────────┬─────────┬───────────┤
│ server               │ L1 │ L2·64B  │ L2·1.5K │ L2·64K  │ split   │ allocs/op │
├──────────────────────┼────┼─────────┼─────────┼─────────┼─────────┼───────────┤
│ armon/go-socks5      │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        89 │
│ things-go/go-socks5  │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        91 │
│ txthinking/socks5    │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        89 │
│ wzshiming/socks5     │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        92 │
│ haxii/socks5         │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        88 │
│ getlantern/go-socks5 │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │       101 │
│ sagernet/sing        │ ✅ │ ❌ lost │ ❌ lost │ ❌ lost │ ❌ lost │       116 │
│ go-gost/x (gost)     │ ✅ │ ❌ lost │ ❌ lost │ ❌ lost │ ❌ lost │       239 │
│ socks0/server        │ ✅ │ ✅      │ ✅      │ ✅      │ ✅      │        94 │
└──────────────────────┴────┴─────────┴─────────┴─────────┴─────────┴───────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│ Clients · cold dial via netem · proxy: armon/go-socks5                      │
│ n=30 c=8 · client↔proxy RTT 0,20,80,200 ms · proxy↔target 20 ms · 64 B      │
├───────────────────┬────┬───────────┬──────────┬────────┬────────┬───────────┤
│ client            │ L2 │ RTTs none │ RTTs u/p │ p50 ms │ max ms │ allocs/op │
├───────────────────┼────┼───────────┼──────────┼────────┼────────┼───────────┤
│ x/net/proxy       │ ❌ │         4 │        5 │  365.1 │  371.7 │        40 │
│ txthinking/socks5 │ ❌ │         4 │        5 │  360.9 │  364.4 │        51 │
│ wzshiming/socks5  │ ❌ │         4 │        5 │  360.8 │  361.0 │        55 │
│ go-gost/gosocks5  │ ❌ │         4 │        5 │  361.1 │  364.2 │        42 │
│ sagernet/sing     │ ❌ │         4 │        5 │  360.7 │  361.5 │        50 │
│ outline-sdk       │ ❌ │         3 │        3 │  280.5 │  280.9 │        41 │
│ socks0 L0         │ ❌ │         4 │        5 │  360.7 │  360.9 │        38 │
│ socks0 L1         │ ❌ │         3 │        3 │  280.7 │  283.8 │        38 │
│ socks0 L1+L2      │ ✅ │         2 │        2 │  200.6 │  203.3 │        40 │
│ ref L1            │ ❌ │         3 │        3 │  280.8 │  281.5 │        46 │
│ ref L1+L2         │ ✅ │         2 │        2 │  200.6 │  202.1 │        46 │
└───────────────────┴────┴───────────┴──────────┴────────┴────────┴───────────┘
  RTTs: client↔proxy round trips to the echo incl. TCP handshake, (p50@200 − p50@0) / 200 ms;
        expect sequential 4 (none) / 5 (u/p), L1 3, L1+L2 2. * = some dials failed.
  p50/max: no-auth at 80 ms RTT. L2, allocs/op: in-process, no-auth.
```

Same with `SERVER=socks0/server`: identical RTT counts, p50 within 0–3 ms (jitter);
socks0 L0/L1/L1+L2 p50 361.2/282.6/200.8 ms there vs 360.7/280.7/200.6 via armon.

- **Servers: 7/9 ready** (exact-size reads on the raw conn, or relaying from the
  parsing `bufio.Reader`). **sing** parses via `bufio.Reader`
  (`protocol/socks/handshake.go:222`) but relays the raw conn (`:228`), losing
  buffered early bytes (up to ~4 KiB) (sing-box v1.14.2 socks/mixed inbounds). **gost**
  (`go-gost/x` v0.15.1): gosocks5 v0.5.0 `ReadRequest` (`socks5.go:519`) reads
  ≤262 bytes, drops what follows the request (first 252 of 1.5/64 KiB lost).
- **socks0/server**: ✅ by construction (one per-conn buffer; leftover bytes go to
  the handler); +5 allocs for cancelable dial ctx + `TCP_USER_TIMEOUT`, fewest
  B/op (Linux 38.0 KB vs 40.4 armon). Bench uses `Filter: AllowAll` (targets are private).
- **Clients:** only outline-sdk is L1; none is L2 (every `Dial` awaits the CONNECT
  reply). The ~100-line `clients/ref.go` takes 2 RTT — half a typical library.
  socks0 matches the best per mode (L0 = x/net, L1 = outline, L1+L2 = ref) with
  fewest allocs; `interop_test.go` (modes × 9 servers × auth × ATYP × 64 B–64 KiB)
  passes except L2 on sing/gost; every client × socks0/server passes (132 cases).

## How it's measured

| | where | what |
| --- | --- | --- |
| server readiness | in-process | auth {none, u/p} × ATYP {IPv4, domain, IPv6} × early {0, 64 B, 1.5 KiB, 64 KiB} × 7 write splits; echo must match. `split` = all multi-write splits |
| client RTTs, p50/max | netem | `-n` cold dials (TCP, handshake, 64 B echo) per client × auth × RTT; RTTs = `(p50@max − p50@0) / max`, cancelling proxy↔target and CPU |
| client L2 | in-process | server withholds the CONNECT reply; does payload arrive? |
| socks0 interop | in-process | `go test`: every mode × server × auth × ATYP × size, echo must match; every client × socks0/server; `http.Transport` write order |
| allocs/op | in-process | one dial + echo, incl. fixed harness share: compare differences |

Failure tags: `lost`/`trunc` (head/tail missing), `garbled`, `hang`, `closed`, `reject`; `bench ready -v` lists failures.

## Loopback lies — what the topology fixes

| loopback | hides | here |
| --- | --- | --- |
| MTU 16 KiB (macOS) / 64 KiB (Linux) | framing bugs: a pipelined message is one segment | veth MTU 1500, GRO/GSO/TSO off: 64 KiB = 46 segments (`./run.sh check`) |
| userspace delay relay | SYN cost: RTT counts off by one | kernel `tc netem`, delays SYN/SYN-ACK too |
| zero RTT | anything to save | client↔proxy 0/20/80/200 ms, proxy↔target 20 ms |
| kernel segmentation | split writes | readiness splits explicitly (bytewise, at/mid field, random), 1.5 ms apart, `TCP_NODELAY` |

```
[client] c0 10.0.1.1 ──veth── p0 10.0.1.2 [proxy] p1 10.0.2.1 ──veth── t0 10.0.2.2 [target]
         netem: whole client↔proxy RTT          netem: whole proxy↔target RTT
```

Three netns in one container (`netem/topo.sh`); client can't reach target.

## Caveats

- Colima idle vCPUs fire netem 0–6 ms late; a `SCHED_IDLE` spinner per vCPU cuts
  it to ~0.02 ms (`SPIN=0` disables). n=30: max is the slowest dial, not p99.
- Readiness is in-process (µs target dial); a server racing a slow dial could lose data.
- Clients used as their READMEs show (gosocks5/txthinking low-level APIs allow
  hand pipelining). L3 (TCP Fast Open) is out of scope.
