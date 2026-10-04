package server_test

// Security review regressions: SSRF, DefaultFilter, oracles.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// SSRF: every alternative encoding of an internal address is denied.
func TestSecOK_DefaultFilterEncodings(t *testing.T) {
	for _, s := range []string{
		"0.0.0.0", "0.1.2.3", "127.0.0.1", "127.255.255.254", "10.1.2.3", "100.64.0.1", "100.100.100.200", // Alibaba metadata
		"169.254.169.254", "169.254.169.253", "169.254.169.123", "169.254.0.23", // AWS/Tencent
		"172.16.0.1", "192.168.1.1", "192.0.0.170", "198.18.0.1", "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
		"::", "::1", "::127.0.0.1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:0:7f00:1", // SIIT
		"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b:1::a00:1", "2002:7f00:1::", "2002:a9fe:a9fe::1",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2", // Teredo
		"2001:db8::1", "2001:10::1", "2001:20::1", "3fff::1", "100::1", "5f00::1",
		"fc00::1", "fd00:ec2::254", "fd00:ec2::253", "fe80::1", "fe80::1%lo0", "fec0::1", "ff02::1", "ff0e::1",
	} {
		ap := netip.AddrPortFrom(netip.MustParseAddr(s), 80)
		if err := server.DefaultFilter(nil, "tcp", ap); err == nil {
			t.Errorf("%s allowed", s)
		}
	}
}

// M3: Azure's WireServer 168.63.129.16 is denied as metadata in every encoding.
func TestSec_DefaultFilterDeniesAzureWireServer(t *testing.T) {
	for _, s := range []string{"168.63.129.16", "::ffff:168.63.129.16", "64:ff9b::a83f:8110", "2002:a83f:8110::"} {
		for _, p := range []uint16{80, 32526} {
			err := server.DefaultFilter(nil, "tcp", netip.AddrPortFrom(netip.MustParseAddr(s), p))
			de, ok := errors.AsType[*server.DeniedError](err)
			if !ok || de.Reason != "metadata" {
				t.Errorf("%s:%d: %v", s, p, err)
			}
		}
	}
	for _, s := range []string{"168.63.129.15", "168.63.129.17"} {
		if err := server.DefaultFilter(nil, "tcp", netip.AddrPortFrom(netip.MustParseAddr(s), 80)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
}

// M2: SelfAddrs are denied as "own address" in every encoding.
func TestSec_SelfAddrs(t *testing.T) {
	type verdict struct {
		addr string
		err  error
	}
	got := make(chan verdict, 16)
	s := &server.Server{
		ErrorLog:  quietLog,
		SelfAddrs: []netip.Prefix{netip.MustParsePrefix("8.8.4.0/24"), netip.MustParsePrefix("2001:4860:4860::8844/128")},
		Handler: server.HandlerFunc(func(_ context.Context, r *server.Request) error {
			for _, a := range []string{"8.8.4.4", "::ffff:8.8.4.4", "64:ff9b::808:404", "2002:808:404::", "2001:4860:4860::8844", "8.8.8.8", "2001:4860:4860::8888"} {
				got <- verdict{a, server.DefaultFilter(r, "tcp", netip.AddrPortFrom(netip.MustParseAddr(a), 443))}
			}
			close(got)
			_, err := r.Reply(wire.ReplyNotAllowed, wire.Addr{})
			return err
		}),
	}
	c := dial(t, serve(t, s))
	_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80")))
	_, _ = io.ReadAll(c)
	for v := range got {
		de, denied := errors.AsType[*server.DeniedError](v.err)
		want := v.addr != "8.8.8.8" && v.addr != "2001:4860:4860::8888"
		if denied != want || denied && de.Reason != "own address" {
			t.Errorf("%s: %v, want denied %v", v.addr, v.err, want)
		}
	}
}

// rawRequest takes any DOMAINNAME bytes, unvalidated.
func rawRequest(cmd wire.Command, name string, port uint16) []byte {
	b := []byte{5, byte(cmd), 0, 3, byte(len(name))}
	b = append(b, name...)
	return binary.BigEndian.AppendUint16(b, port)
}

// SSRF: names resolving to loopback never reach it through the zero ConnectHandler.
func TestSecOK_NumericNameForms(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	proxy := serve(t, &server.Server{ErrorLog: quietLog}) // zero value: DefaultFilter
	for _, name := range []string{
		"127.1", "127.0.1", "0x7f.1", "0x7f000001", "2130706433", "017700000001", "0177.0.0.1", "127.000.000.001",
		"127.0.0.1.", "localhost", "localhost.", "LOCALHOST", "localhost.localdomain", "ip6-localhost",
		"0", "0.0.0.0", "::1", "::ffff:127.0.0.1", "[::1]", "127.0.0.1%lo0", "::ffff:7f00:1", "0:0:0:0:0:ffff:7f00:1",
		"127.0.0.1\x00.example.com", "127.0.0.1 ", " 127.0.0.1", "127.0.0.1\t",
	} {
		c := dial(t, proxy)
		// Some forms resolve to a public IP ("0177.0.0.1" on macOS): no reply is fine.
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(cat(greeting(0), rawRequest(wire.CmdConnect, name, port)))
		if got, _ := io.ReadAll(c); len(got) >= 4 && got[3] == 0 {
			t.Errorf("%q: reply %x", name, got)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::", "::1", "::"} {
		c := dial(t, proxy)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, netip.AddrPortFrom(netip.MustParseAddr(ip), port).String())))
		got, _ := io.ReadAll(c)
		if len(got) < 4 || got[3] != byte(wire.ReplyNotAllowed) {
			t.Errorf("%s: %x", ip, got)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("loopback target accepted %d conns", n)
	}
}

// L6: BIND replies 04 before listening for internal and unknown names alike.
func TestSec_BindNoNameExistenceOracle(t *testing.T) {
	s := &server.Server{ErrorLog: quietLog, Handler: &server.Mux{
		Connect: &server.ConnectHandler{},
		Bind:    &server.BindHandler{AcceptTimeout: 5 * time.Second},
	}}
	proxy := serve(t, s)
	first := func(cmd wire.Command, name string) wire.Reply {
		c := dial(t, proxy)
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write(cat(greeting(0), rawRequest(cmd, name, 80)))
		expect(t, c, []byte{5, 0})
		rep, _ := readReply(t, c, cmd)
		return rep
	}
	internal, unknown := "localhost", "no-such-host.invalid"
	ci, cu := first(wire.CmdConnect, internal), first(wire.CmdConnect, unknown)
	bi, bu := first(wire.CmdBind, internal), first(wire.CmdBind, unknown)
	if ci != cu || bi != bu || bi != wire.ReplyHostUnreachable {
		t.Fatalf("CONNECT internal %v / unknown %v; BIND internal %v / unknown %v: want all 04", ci, cu, bi, bu)
	}
	c := dial(t, proxy)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = c.Write(cat(greeting(0), request(wire.CmdBind, "127.0.0.1:80")))
	expect(t, c, []byte{5, 0})
	if rep, _ := readReply(t, c, wire.CmdBind); rep != wire.ReplyNotAllowed {
		t.Fatalf("BIND 127.0.0.1: %v, want 02", rep)
	}
}

func localIP(t *testing.T) netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skip(err)
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() && !p.Addr().IsLoopback() {
			return p.Addr()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return netip.Addr{}
}

// ownOnly is DefaultFilter's own-address rule alone, so a private IP can stand in for a public one.
func ownOnly(r *server.Request, _ string, a netip.AddrPort) error {
	if ta, ok := r.LocalAddr.(*net.TCPAddr); ok && ta.AddrPort().Addr().Unmap() == a.Addr() {
		return &server.DeniedError{Addr: a, Reason: "own address"}
	}
	return nil
}

// L3: no port-scan oracle on the proxy's other addresses: refused before connecting.
func TestSec_OwnHostNoPortScanOracle(t *testing.T) {
	ip := localIP(t)
	svc, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Skip(err)
	}
	defer svc.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := svc.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	closedLn, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	closed := closedLn.Addr().(*net.TCPAddr).Port
	closedLn.Close()
	open := svc.Addr().(*net.TCPAddr).Port

	proxy := serve(t, &server.Server{ErrorLog: quietLog, Handler: &server.ConnectHandler{Filter: ownOnly}})
	reply := func(port int) wire.Reply {
		c := dial(t, proxy)
		_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, net.JoinHostPort(ip.String(), strconv.Itoa(port)))))
		expect(t, c, []byte{5, 0})
		rep, _ := readReply(t, c, wire.CmdConnect)
		return rep
	}
	repOpen, repClosed := reply(open), reply(closed)
	time.Sleep(50 * time.Millisecond)
	if repOpen != wire.ReplyNotAllowed || repClosed != wire.ReplyNotAllowed || accepted.Load() != 0 {
		t.Fatalf("%v: open port → %v, closed → %v, service accepted %d; want 02, 02, 0", ip, repOpen, repClosed, accepted.Load())
	}
}
