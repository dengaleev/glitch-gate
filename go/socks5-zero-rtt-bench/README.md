# socks5-zero-rtt-bench

How close do Go SOCKS5 libraries get to zero RTT on a cold dial? **L1
(pipelining):** the client commits to one auth method and sends greeting +
[auth] + CONNECT at once: 1 handshake RTT instead of 2 (no-auth) or 3
(user/pass). **L2 (early data):** it also sends payload before the CONNECT
reply: SOCKS adds 0 RTT over TCP. Servers must keep pipelined and early bytes;
clients are scored by round trips to the first response byte.

## Run

```sh
./run.sh                     # all, in a netem topology (Docker; macOS: colima start)
./run.sh -n 50 -rtts 0,200   # flags go to `bench rtt`
./run.sh check               # verify the topology: RTTs, MTU, offloads, segmentation
go test ./...                # harness + library smoke tests, no Docker
go test -bench . ./...       # allocs/op per server and client
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
└──────────────────────┴────┴─────────┴─────────┴─────────┴─────────┴───────────┘
  sagernet/sing · L2·64B: noauth 127.0.0.1 64B one: lost: none of 64 early bytes reached the target
  sagernet/sing · L2·1.5K: noauth 127.0.0.1 1536B one: lost: none of 1536 early bytes reached the target
  sagernet/sing · L2·64K: noauth 127.0.0.1 65536B one: lost: first 4083 of 65536 early bytes never reached the target
  sagernet/sing · split: noauth 127.0.0.1 64B hs-bytes: lost: none of 64 early bytes reached the target
┌─────────────────────────────────────────────────────────────────────────────┐
│ Clients · cold dial via netem · proxy: armon/go-socks5                      │
│ n=30 c=8 · client↔proxy RTT 0,20,80,200 ms · proxy↔target 20 ms · 64 B      │
├───────────────────┬────┬───────────┬──────────┬────────┬────────┬───────────┤
│ client            │ L2 │ RTTs none │ RTTs u/p │ p50 ms │ max ms │ allocs/op │
├───────────────────┼────┼───────────┼──────────┼────────┼────────┼───────────┤
│ x/net/proxy       │ ❌ │         4 │        5 │  360.7 │  362.8 │        40 │
│ txthinking/socks5 │ ❌ │         4 │        5 │  360.6 │  360.8 │        51 │
│ wzshiming/socks5  │ ❌ │         4 │        5 │  361.0 │  361.3 │        55 │
│ go-gost/gosocks5  │ ❌ │         4 │        5 │  360.6 │  360.8 │        42 │
│ sagernet/sing     │ ❌ │         4 │        5 │  361.0 │  361.3 │        50 │
│ outline-sdk       │ ❌ │         3 │        3 │  280.8 │  281.7 │        41 │
│ ref L1            │ ❌ │         3 │        3 │  280.6 │  281.1 │        46 │
│ ref L1+L2         │ ✅ │         2 │        2 │  200.3 │  200.7 │        45 │
└───────────────────┴────┴───────────┴──────────┴────────┴────────┴───────────┘
  RTTs: client↔proxy round trips to the echo incl. TCP handshake, (p50@200 − p50@0) / 200 ms;
        expect sequential 4 (none) / 5 (u/p), L1 3, L1+L2 2. * = some dials failed.
  p50/max: no-auth at 80 ms RTT. L2, allocs/op: in-process, no-auth.
```

- **Servers: 6/7 ready** — exact-size reads on the raw conn (txthinking,
  wzshiming) or relaying from the parsing `bufio.Reader` (armon + forks,
  things-go). **`sagernet/sing` loses early data:**
  `protocol/socks/handshake.go:222` parses via a `bufio.Reader`, `:228` hands
  the handler the raw conn (`NewLazyConn(conn)`), dropping up to 4 KiB buffered
  past the request. sing-box v1.14.2 socks/mixed inbounds call it this way
  (`protocol/socks/inbound.go:75`).
- **Clients: only outline-sdk is L1** (3 RTT incl. TCP, any auth). The rest are
  sequential: 4 no-auth, 5 user/pass (x/net and wzshiming even advertise both
  methods).
- **No library is L2**: every `Dial` waits for the CONNECT reply. The ~100-line
  reference L1+L2 client (`clients/ref.go`) takes 2 RTT (TCP + handshake with
  data) — half a typical library.

## How it's measured

| | where | what |
| --- | --- | --- |
| server readiness | in-process | auth {none, u/p} × ATYP {IPv4, domain, IPv6} × early {0, 64 B, 1.5 KiB, 64 KiB} × 7 write splits; echo must match. `split` = all multi-write splits |
| client RTTs, p50/max | netem | `-n` cold dials (TCP, handshake, 64 B echo) per client × auth × RTT; RTTs = `(p50@max − p50@0) / max`, cancelling proxy↔target and CPU |
| client L2 | in-process | server withholds the CONNECT reply; does payload arrive? |
| allocs/op | in-process | one dial + echo, incl. fixed harness share: compare differences |

Failure tags: `lost`/`trunc` (head/tail missing), `garbled`, `hang`, `closed`,
`reject`; `bench ready -v` lists every failing case.

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
Each RTT sits on one direction: counted exchanges are request→response, so one
RTT per round trip. Proxy: first server passing every readiness cell (armon),
so early data survives.

## Caveats

- **Colima timer jitter**: idle vCPUs fire netem 0–6 ms late; a `SCHED_IDLE`
  spinner per vCPU gets ~0.02 ms but keeps host CPUs busy (`SPIN=0` disables).
- **Readiness is in-process** (µs target dial): a server reading the client
  concurrently with a slow target dial could pass here yet lose data; none does.
- **Clients are used as their READMEs show**; gosocks5's and txthinking's
  low-level APIs allow hand pipelining.
- **L3 (TCP Fast Open)** is out of scope.
- n=30: the tail column is the slowest dial, not a p99.
