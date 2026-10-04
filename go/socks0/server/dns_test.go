package server_test

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// dnsServer serves A, AAAA and NXDOMAIN over UDP for a PreferGo net.Resolver.
func dnsServer(t testing.TB, zone map[string][]string) *net.Resolver {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if resp := dnsAnswer(buf[:n], zone); resp != nil {
				_, _ = pc.WriteTo(resp, from)
			}
		}
	})
	t.Cleanup(func() { pc.Close(); wg.Wait() })
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "udp", pc.LocalAddr().String())
	}}
}

func dnsAnswer(q []byte, zone map[string][]string) []byte {
	if len(q) < 12 {
		return nil
	}
	var labels []string
	i := 12
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	if i+5 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1:])
	question := q[12 : i+5]
	var answers [][]byte
	ips, found := zone[strings.ToLower(strings.Join(labels, "."))]
	for _, s := range ips {
		ip := netip.MustParseAddr(s)
		if ip.Is4() && qtype == 1 || ip.Is6() && qtype == 28 {
			answers = append(answers, ip.AsSlice())
		}
	}
	rcode := uint16(0)
	if !found {
		rcode = 3
	}
	r := binary.BigEndian.AppendUint16(nil, binary.BigEndian.Uint16(q))
	r = binary.BigEndian.AppendUint16(r, 0x8180|rcode)
	r = binary.BigEndian.AppendUint16(r, 1)
	r = binary.BigEndian.AppendUint16(r, uint16(len(answers)))
	r = append(r, 0, 0, 0, 0)
	r = append(r, question...)
	for _, a := range answers {
		r = append(r, 0xC0, 12)
		r = binary.BigEndian.AppendUint16(r, qtype)
		r = append(r, 0, 1, 0, 0, 0, 60)
		r = binary.BigEndian.AppendUint16(r, uint16(len(a)))
		r = append(r, a...)
	}
	return r
}
