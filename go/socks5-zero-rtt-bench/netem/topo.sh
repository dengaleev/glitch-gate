#!/bin/sh
# Container entrypoint: three netns wired like a real link, then the benchmark.
#
#   [client] c0 10.0.1.1 ──veth── 10.0.1.2 p0 [proxy] p1 10.0.2.1 ──veth── 10.0.2.2 t0 [target]
#            netem on c0 egress:                       netem on p1 egress:
#            whole client↔proxy RTT (set by bench rtt) whole proxy↔target RTT ($PT_RTT ms)
#
# - One-sided delay: each counted exchange is request→response, so it costs
#   exactly one RTT, and bench rtt only touches its own netns.
# - Static ARP (no resolution mid-dial), IPv6 off, proxy doesn't forward.
# - SPIN=1: a SCHED_IDLE spinner per CPU keeps colima vCPUs awake; idle ones
#   fire netem timers 0–6 ms late (~0.02 ms with spinners).
#
# Usage: topo.sh [bench rtt flags...]   bench ready + bench rtt per $SERVER
#        topo.sh check                  measure the topology itself
set -eu

PT_RTT=${PT_RTT:-20} # proxy↔target RTT, ms
SPIN=${SPIN:-1}
SERVER=${SERVER:-} # proxy name(s), comma-separated; default: bench proxy -pick
USER_=bench PASS_=bench
C=10.0.1.1 P=10.0.1.2 PT=10.0.2.1 T=10.0.2.2

at() {
	ns=$1
	shift
	ip netns exec "$ns" "$@"
}

for ns in client proxy target; do
	ip netns add $ns
	ip -n $ns link set lo up
	at $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
done
at proxy sysctl -qw net.ipv4.ip_forward=0

ip link add c0 netns client type veth peer name p0 netns proxy
ip link add p1 netns proxy type veth peer name t0 netns target
wire() { # NS DEV IP
	ip -n $1 link set $2 mtu 1500 up
	ip -n $1 addr add $3/24 dev $2
	at $1 ethtool -K $2 gro off gso off tso off
}
wire client c0 $C
wire proxy p0 $P
wire proxy p1 $PT
wire target t0 $T
mac() { ip -n $1 -br link show dev $2 | awk '{print $3}'; }
static_arp() { # NS DEV IP PEER_NS PEER_DEV
	ip -n $1 neigh replace $3 lladdr "$(mac $4 $5)" dev $2 nud permanent
}
static_arp client c0 $P proxy p0
static_arp proxy p0 $C client c0
static_arp proxy p1 $T target t0
static_arp target t0 $PT proxy p1

at client tc qdisc replace dev c0 root netem delay 0ms
at proxy tc qdisc replace dev p1 root netem delay ${PT_RTT}ms

if [ "$SPIN" = 1 ]; then # no cleanup: we are PID 1
	for _ in $(seq "$(nproc)"); do chrt -i 0 sh -c 'while :; do :; done' & done
fi

wait_listen() { # NS PORT PID
	for _ in $(seq 600); do
		[ -n "$(at $1 ss -Hltn "sport = :$2")" ] && return 0
		kill -0 $3 2>/dev/null || {
			echo "topo: listener on :$2 in $1 exited" >&2
			exit 1
		}
		sleep 0.1
	done
	echo "topo: timed out waiting for :$2 in $1" >&2
	exit 1
}

check() {
	echo "== interfaces (MTU, offloads)"
	for x in client:c0 proxy:p0 proxy:p1 target:t0; do
		ns=${x%:*} dev=${x#*:}
		printf '%-6s %-3s mtu %s  %s\n' $ns $dev "$(at $ns cat /sys/class/net/$dev/mtu)" \
			"$(at $ns ethtool -k $dev | awk -F': ' '/^(tcp-segmentation|generic-segmentation|generic-receive)-offload/{printf "%s=%s ", $1, $2}')"
	done
	echo "== isolation"
	if at client ping -c1 -W1 $T >/dev/null 2>&1; then echo "FAIL: client reaches target"; else echo "ok: client cannot reach target"; fi
	at client tc qdisc replace dev c0 root netem delay 80ms
	echo "== ICMP RTT (client↔proxy netem 80 ms, proxy↔target netem $PT_RTT ms, SPIN=$SPIN)"
	printf 'client→proxy  '
	at client ping -qc20 -i0.1 $P | tail -1
	printf 'proxy→target  '
	at proxy ping -qc20 -i0.1 $T | tail -1
	at proxy socat TCP-LISTEN:9,bind=$P,fork,reuseaddr EXEC:cat &
	pid=$!
	wait_listen proxy 9 $pid
	echo "== TCP client→proxy: kernel RTT estimate of a fresh connection (ss -ti)"
	(sleep 1 | at client socat - TCP:$P:9 >/dev/null) &
	sleep 0.5
	at client ss -Htin dst $P | grep -oE ' (rtt|minrtt|mss):[^ ]*' | tr '\n' ' '
	echo
	wait $!
	echo "== 64 KiB request client→proxy, segments seen on p0"
	head -c 65536 /dev/zero >/tmp/64k
	at proxy tcpdump -i p0 -nn -q -l "tcp and src $C and dst port 9" >/tmp/dump 2>/dev/null &
	dump=$!
	sleep 1
	at client socat - TCP:$P:9 </tmp/64k >/dev/null
	sleep 0.5
	kill $dump
	wait $dump 2>/dev/null || true
	awk '{n=$NF+0} n>0 {c++; s+=n; if (n>m) m=n} END {printf "data segments %d, payload bytes %d, largest %d\n", c, s, m}' /tmp/dump
}

if [ "${1:-}" = check ]; then
	check
	exit 0
fi

# SERVER: one proxy name, or several separated by commas: one clients table each.
SERVER=${SERVER:-$(bench proxy -pick)}
at target bench target -listen $T:7 &
tpid=$!
wait_listen target 7 $tpid

bench ready
rest=$SERVER,
while [ -n "$rest" ]; do
	srv=${rest%%,*} rest=${rest#*,}
	# Not via at(): $! must be the proxy itself, to kill it.
	ip netns exec proxy bench proxy -listen $P:1080 -server "$srv" &
	p0=$!
	ip netns exec proxy bench proxy -listen $P:1081 -server "$srv" -user $USER_ -pass $PASS_ &
	p1=$!
	wait_listen proxy 1080 $p0
	wait_listen proxy 1081 $p1
	echo
	at client bench rtt -proxy $P -target $T:7 -dev c0 -user $USER_ -pass $PASS_ \
		-server "$srv" -pt-rtt $PT_RTT "$@"
	kill $p0 $p1
	wait $p0 $p1 2>/dev/null || true
done
