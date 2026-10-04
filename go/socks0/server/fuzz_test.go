package server_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// model is the reference parser for fuzzServer's config: [UserPass{u: p}, NoAuth], any USERID.
func model(b []byte) (hsLen int, ok bool) {
	if len(b) == 0 {
		return 0, false
	}
	switch b[0] {
	case 4:
		cmd, _, _, n, err := wire.ParseRequest4(b)
		return n, err == nil && (cmd == wire.CmdConnect || cmd == wire.CmdBind)
	case 5:
	default:
		return 0, false
	}
	methods, n, err := wire.ParseGreeting(nil, b)
	if err != nil {
		return 0, false
	}
	switch {
	case slices.Contains(methods, wire.MethodUserPass):
		user, pass, m, err := wire.ParseUserPass(b[n:])
		if err != nil || string(user) != "u" || string(pass) != "p" {
			return 0, false
		}
		n += m
	case !slices.Contains(methods, wire.MethodNoAuth):
		return 0, false
	}
	_, _, m, err := wire.ParseRequest(b[n:])
	return n + m, err == nil
}

// fuzzServer's handler reads the post-reply bytes the way mode selects.
func fuzzServer(mode byte, peek int, want int, got *[]byte, gotErr *error) *server.Server {
	s := &server.Server{
		Versions:         server.V4 | server.V5,
		Auth:             []server.Authenticator{server.UserPass{Users: map[string]string{"u": "p"}}, server.NoAuth{}},
		UserID:           func(context.Context, []byte) (any, error) { return nil, nil },
		ErrorLog:         quietLog,
		HandshakeTimeout: 5 * time.Second, // hang guard; cases end sooner
	}
	s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
		var pre []byte
		if peek > 0 {
			b, err := r.Peek(ctx, min(peek, want))
			if err != nil {
				*gotErr = err
				return err
			}
			pre = bytes.Clone(b)
		}
		c, err := r.Reply(0, wire.Addr{})
		if err != nil {
			*gotErr = err
			return err
		}
		*got, *gotErr = readMode(ctx, c, mode, want)
		if !bytes.HasPrefix(*got, pre) {
			*gotErr = errors.New("Conn does not start with the peeked bytes")
		}
		return nil
	})
	return s
}

func readMode(ctx context.Context, c *server.Conn, mode byte, want int) ([]byte, error) {
	switch mode % 4 {
	case 0:
		b := make([]byte, want)
		_, err := io.ReadFull(c, b)
		return b, err
	case 1:
		if want == 0 { // WriteTo would wait for an EOF that never comes
			return nil, nil
		}
		var b bytes.Buffer
		_, err := c.WriteTo(&limitWriter{&b, want})
		if errors.Is(err, errFull) {
			err = nil
		}
		return b.Bytes(), err
	case 2:
		nc, buf := c.NetConn()
		buf = bytes.Clone(buf)
		if len(buf) > want {
			return buf, errors.New("NetConn buffered more than was sent")
		}
		rest := make([]byte, want-len(buf))
		_, err := io.ReadFull(nc, rest)
		return append(buf, rest...), err
	}
	tgtSrv, tgtCli := net.Pipe()
	got := make(chan []byte, 1)
	go func() {
		b := make([]byte, want)
		n, _ := io.ReadFull(tgtCli, b)
		tgtCli.Close()
		got <- b[:n]
	}()
	_, _, err := server.Relay(ctx, c, tgtSrv)
	return <-got, err
}

// No panic or hang; after a valid handshake every read path gets exactly input[hsLen:].
func FuzzServeConn(f *testing.F) {
	seeds := [][]byte{
		cat(greeting(0), request(wire.CmdConnect, "1.2.3.4:80"), []byte("early")),
		cat(greeting(0, 2), userPass("u", "p"), request(wire.CmdConnect, "example.com:443"), payload()[:3000]),
		cat(greeting(2), userPass("u", "x"), request(wire.CmdConnect, "[::1]:1")),
		cat(greeting(1), request(wire.CmdConnect, "1.2.3.4:80")),
		cat(greeting(0), request(wire.CmdUDPAssociate, "0.0.0.0:0")),
		cat(greeting(0), []byte{5, 1, 0, 9}),
		{4, 1, 0, 80, 1, 2, 3, 4, 'i', 'd', 0, 'x', 'y'},
		{4, 2, 0, 80, 0, 0, 0, 1, 0, 'h', 'o', 's', 't', 0, 'e', 'a', 'r', 'l', 'y'},
		{4, 3, 0, 80, 1, 2, 3, 4, 0},
		[]byte("GET / HTTP/1.1\r\n\r\n"),
		{},
	}
	for i, s := range seeds {
		f.Add(s, []byte{byte(i), 3, 7}, byte(i), byte(i%3))
	}
	f.Fuzz(func(t *testing.T, data, cuts []byte, mode, peek byte) {
		hsLen, complete := model(data)
		want := len(data) - hsLen
		var got []byte
		var gotErr error
		s := fuzzServer(mode, int(peek)*int(peek%2), want, &got, &gotErr)
		cli, srv := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- s.ServeConn(context.Background(), srv) }()
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, cli) })
		wg.Go(func() {
			last := 0
			for _, c := range cuts {
				if i := last + int(c); i < len(data) {
					if _, err := cli.Write(data[last:i]); err != nil {
						return
					}
					last = i
				}
			}
			_, _ = cli.Write(data[last:])
			if !complete {
				cli.Close() // the server must give up
			}
		})
		var err error
		select {
		case err = <-errc:
		case <-time.After(10 * time.Second):
			t.Fatalf("ServeConn hangs on %x", data)
		}
		cli.Close()
		wg.Wait()
		if complete != (err == nil) && !(complete && errors.Is(err, server.ErrNoReply)) {
			t.Fatalf("%x: complete %v, ServeConn %v", data, complete, err)
		}
		if complete && (gotErr != nil || !bytes.Equal(got, data[hsLen:])) {
			t.Fatalf("%x (mode %d, peek %d): handler got %x, %v; want %x", data, mode%4, peek, got, gotErr, data[hsLen:])
		}
	})
}

// Fuzzed AuthConn message lengths leave the request and early data intact.
func FuzzAuthConn(f *testing.F) {
	f.Add([]byte{3, 0, 7}, []byte("early"), []byte{1, 2})
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte{255, 255, 255, 255, 255}, payload()[:2000], []byte{0, 100})
	f.Fuzz(func(t *testing.T, lens, early, cuts []byte) {
		lens = lens[:min(len(lens), 8)]
		var msgs []byte
		for i, l := range lens {
			msgs = append(msgs, bytes.Repeat([]byte{byte(i)}, int(l))...)
		}
		data := cat(greeting(0x80), msgs, request(wire.CmdConnect, "example.com:80"), early)
		var gotMsgs [][]byte
		var gotEarly []byte
		var addr wire.Addr
		s := &server.Server{ErrorLog: quietLog}
		s.Auth = []server.Authenticator{authFunc(func(_ context.Context, c *server.AuthConn) (any, error) {
			for _, l := range lens {
				m, err := c.ReadMessage(func(b []byte) (int, error) {
					if len(b) < int(l) {
						return int(l), wire.ErrIncomplete
					}
					return int(l), nil
				})
				if err != nil {
					return nil, err
				}
				if cap(m) != len(m) {
					t.Errorf("message capacity %d > length %d", cap(m), len(m))
				}
				gotMsgs = append(gotMsgs, bytes.Clone(m))
			}
			return nil, nil
		})}
		s.Handler = server.HandlerFunc(func(_ context.Context, r *server.Request) error {
			addr = r.Addr
			c, err := r.Reply(0, wire.Addr{})
			if err != nil {
				return err
			}
			gotEarly = make([]byte, len(early))
			_, err = io.ReadFull(c, gotEarly)
			return err
		})
		cli, srv := net.Pipe()
		errc := make(chan error, 1)
		go func() { errc <- s.ServeConn(context.Background(), srv) }()
		var wg sync.WaitGroup
		wg.Go(func() { _, _ = io.Copy(io.Discard, cli) })
		wg.Go(func() {
			last := 0
			for _, c := range cuts {
				if i := last + int(c); i < len(data) {
					_, _ = cli.Write(data[last:i])
					last = i
				}
			}
			_, _ = cli.Write(data[last:])
		})
		err := <-errc
		cli.Close()
		wg.Wait()
		if err != nil || addr.String() != "example.com:80" || !bytes.Equal(gotEarly, early) || len(gotMsgs) != len(lens) {
			t.Fatalf("err %v addr %v early %d/%d msgs %d/%d", err, addr, len(gotEarly), len(early), len(gotMsgs), len(lens))
		}
		for i, m := range gotMsgs {
			if !bytes.Equal(m, bytes.Repeat([]byte{byte(i)}, int(lens[i]))) {
				t.Fatalf("message %d: %x", i, m)
			}
		}
	})
}
