module github.com/dengaleev/glitch-gate/go/socks5-pipelining-bench

go 1.26

require (
	github.com/dengaleev/glitch-gate/go/socks5-0rtt-pipelining v0.0.0
	github.com/jedib0t/go-pretty/v6 v6.8.1
	github.com/txthinking/socks5 v0.0.0-20260601051520-339b044ab0eb
)

replace github.com/dengaleev/glitch-gate/go/socks5-0rtt-pipelining => ../socks5-0rtt-pipelining

require (
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/database64128/netx-go v0.1.1 // indirect
	github.com/database64128/tfo-go/v2 v2.3.3 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/txthinking/runnergroup v0.0.0-20250224021307-5864ffeb65ae // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
)
