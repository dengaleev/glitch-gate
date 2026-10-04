package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(format string, args ...any) {
	e.mu.Lock()
	e.log = append(e.log, fmt.Sprintf(format, args...))
	e.mu.Unlock()
}

func (e *events) get() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.log)
}

func errTag(err error) string {
	if err != nil {
		return "err"
	}
	return "ok"
}

// trace logs each hook as "<tag>:<Hook>".
func (e *events) trace(tag string) *socks0.ClientTrace {
	return &socks0.ClientTrace{
		ConnectStart:   func(network, addr string) { e.add("%s:ConnectStart", tag) },
		ConnectDone:    func(network, addr string, err error) { e.add("%s:ConnectDone %s", tag, errTag(err)) },
		WroteHandshake: func(err error) { e.add("%s:WroteHandshake %s", tag, errTag(err)) },
		GotMethod:      func(m wire.Method) { e.add("%s:GotMethod %v", tag, m) },
		AuthDone:       func(err error) { e.add("%s:AuthDone %s", tag, errTag(err)) },
		GotReply:       func(rep wire.Reply, bound wire.Addr) { e.add("%s:GotReply %v %v", tag, rep, bound) },
		HandshakeDone:  func(err error) { e.add("%s:HandshakeDone %s", tag, errTag(err)) },
	}
}

func only(log []string, tag string) []string {
	var out []string
	for _, l := range log {
		if s, ok := strings.CutPrefix(l, tag+":"); ok {
			out = append(out, s)
		}
	}
	return out
}

var fullTrace = []string{
	"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod username/password",
	"AuthDone ok", "GotReply succeeded 192.0.2.1:1080", "HandshakeDone ok",
}

func TestTraceOrder(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var ev events
			cfg := &socks0.Config{Mode: mode, Auth: socks0.UserPass{}, Trace: ev.trace("cfg")}
			ctx := socks0.WithClientTrace(t.Context(), ev.trace("ctx1"))
			ctx = socks0.WithClientTrace(ctx, ev.trace("ctx2"))
			d := &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Config: cfg}
			c, err := d.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write([]byte("x"))
			readN(t, c, 1)
			log := ev.get()
			for _, tag := range []string{"cfg", "ctx1", "ctx2"} {
				if got := only(log, tag); !slices.Equal(got, fullTrace) {
					t.Errorf("%s hooks: %q", tag, got)
				}
			}
			// Config.Trace first, then the ctx's, newest first.
			if l := log[:3]; !slices.Equal(l, []string{"cfg:ConnectStart", "ctx2:ConnectStart", "ctx1:ConnectStart"}) {
				t.Errorf("order %q", l)
			}
		})
	}
}

// HandshakeDone runs iff WroteHandshake ran.
func TestTraceFailures(t *testing.T) {
	for _, tt := range []struct {
		name string
		d    func(t *testing.T) *socks0.Dialer
		mode socks0.Mode
		want []string
	}{
		{"config", func(t *testing.T) *socks0.Dialer {
			return &socks0.Dialer{ProxyAddr: listen(t, proxy{}.serve), Config: &socks0.Config{Auth: interactive{0x80}}}
		}, socks0.ModePipelined, nil},
		{"proxy dial", func(t *testing.T) *socks0.Dialer {
			return &socks0.Dialer{ProxyDial: func(context.Context, string, string) (net.Conn, error) { return nil, errTest }}
		}, socks0.ModePipelined, []string{"ConnectStart", "ConnectDone err"}},
		{"method", func(t *testing.T) *socks0.Dialer {
			return &socks0.Dialer{ProxyAddr: listen(t, scripted([]byte{5, 0xFF}, false))}
		}, socks0.ModeSequential, []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod no acceptable methods", "HandshakeDone err"}},
		{"auth", func(t *testing.T) *socks0.Dialer {
			return &socks0.Dialer{ProxyAddr: listen(t, proxy{status: 1}.serve), Config: &socks0.Config{Auth: socks0.UserPass{}}}
		}, socks0.ModeSequential, []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod username/password", "AuthDone err", "HandshakeDone err"}},
		{"reply", func(t *testing.T) *socks0.Dialer {
			return &socks0.Dialer{ProxyAddr: listen(t, proxy{rep: 2}.serve)}
		}, socks0.ModeEarly, []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "GotMethod no auth", "GotReply connection not allowed by ruleset 192.0.2.1:1080", "HandshakeDone err"}},
	} {
		for _, mode := range modes {
			if tt.name == "config" && mode == socks0.ModeSequential {
				continue // valid in L0
			}
			t.Run(tt.name+"/"+mode.String(), func(t *testing.T) {
				var ev events
				d := tt.d(t)
				if d.Config == nil {
					d.Config = new(socks0.Config)
				}
				d.Config.Mode = mode
				d.Config.Trace = ev.trace("t")
				handshakeErr(t.Context(), d, "example.com:80")
				if got := only(ev.get(), "t"); !slices.Equal(got, tt.want) {
					t.Errorf("hooks %q\nwant  %q", got, tt.want)
				}
			})
		}
	}
}

func TestTraceClient(t *testing.T) {
	for _, mode := range modes {
		t.Run(mode.String(), func(t *testing.T) {
			var ev events
			cfg := &socks0.Config{Mode: mode, Auth: socks0.UserPass{}, Trace: ev.trace("cfg")}
			// Implicit handshake: Config.Trace only.
			c, _ := client(t, proxy{}.serve, cfg)
			c.Write([]byte("x"))
			readN(t, c, 1)
			if got := only(ev.get(), "cfg"); !slices.Equal(got, fullTrace[2:]) {
				t.Errorf("implicit: %q", got)
			}
			// HandshakeContext starting the handshake adds the ctx's hooks.
			ev = events{}
			c, _ = client(t, proxy{}.serve, cfg)
			ctx := socks0.WithClientTrace(t.Context(), ev.trace("ctx"))
			if err := c.HandshakeContext(ctx); err != nil {
				t.Fatal(err)
			}
			log := ev.get()
			if !slices.Equal(only(log, "cfg"), fullTrace[2:]) || !slices.Equal(only(log, "ctx"), fullTrace[2:]) {
				t.Errorf("HandshakeContext: %q", log)
			}
		})
	}
}

func TestTraceEarlyClose(t *testing.T) {
	var ev events
	d := &socks0.Dialer{ProxyAddr: listen(t, scripted(nil, true)), Config: &socks0.Config{Mode: socks0.ModeEarly, Trace: ev.trace("t")}}
	c, err := d.DialContext(t.Context(), "tcp", "example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("x"))
	c.Close()
	if got := only(ev.get(), "t"); !slices.Equal(got, []string{"ConnectStart", "ConnectDone ok", "WroteHandshake ok", "HandshakeDone err"}) {
		t.Errorf("hooks %q", got)
	}
	if _, err := c.Read(nil); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read = %v", err)
	}
}

func TestWithClientTrace(t *testing.T) {
	ctx := t.Context()
	if socks0.WithClientTrace(ctx, nil) != ctx || socks0.ContextClientTrace(ctx) != nil {
		t.Error("nil trace")
	}
	var ev events
	a := &socks0.ClientTrace{GotReply: func(wire.Reply, wire.Addr) { ev.add("a") }, ConnectDone: func(string, string, error) { ev.add("a connected") }}
	b := &socks0.ClientTrace{GotReply: func(wire.Reply, wire.Addr) { ev.add("b") }, HandshakeDone: func(error) { ev.add("b done") }}
	ctx = socks0.WithClientTrace(ctx, a)
	if socks0.ContextClientTrace(ctx) != a {
		t.Error("ContextClientTrace")
	}
	ctx = socks0.WithClientTrace(ctx, b)
	tr := socks0.ContextClientTrace(ctx)
	tr.GotReply(0, wire.Addr{})
	tr.HandshakeDone(nil)
	tr.ConnectDone("tcp", "", nil)
	if tr.ConnectStart != nil {
		t.Error("ConnectStart composed from nils")
	}
	if got := ev.get(); !slices.Equal(got, []string{"b", "a", "b done", "a connected"}) {
		t.Errorf("composed hooks ran %q", got)
	}
}
