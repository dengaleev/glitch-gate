package server_test

// Relay and the Conn copy paths: half-close, errors, splice delegation, no cross-talk.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/server"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type relayResult struct {
	up, down int64
	err      error
}

func startRelay(rl *server.Relayer, ctx context.Context, client, target net.Conn) <-chan relayResult {
	res := make(chan relayResult, 1)
	go func() {
		up, down, err := rl.Relay(ctx, client, target)
		res <- relayResult{up, down, err}
	}()
	return res
}

func waitRelay(t testing.TB, res <-chan relayResult) relayResult {
	t.Helper()
	select {
	case r := <-res:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("Relay did not return")
		return relayResult{}
	}
}

func TestRelayHalfClose(t *testing.T) {
	for _, clientFirst := range []bool{true, false} {
		t.Run(fmt.Sprint("clientFirst=", clientFirst), func(t *testing.T) {
			cli, cliSrv := tcpPair(t)
			tgtSrv, tgt := tcpPair(t)
			res := startRelay(new(server.Relayer), t.Context(), cliSrv, tgtSrv)
			up, down := payload()[:300<<10], payload()[1<<10:200<<10]
			first, second := cli, tgt
			firstData, secondData := up, down
			if !clientFirst {
				first, second, firstData, secondData = tgt, cli, down, up
			}
			go func() { _, _ = first.Write(firstData); _ = first.CloseWrite() }()
			if got, err := io.ReadAll(second); err != nil || !bytes.Equal(got, firstData) {
				t.Fatalf("first direction: %d bytes, %v", len(got), err)
			}
			// The other direction still works after the half-close.
			go func() { _, _ = second.Write(secondData); _ = second.CloseWrite() }()
			if got, err := io.ReadAll(first); err != nil || !bytes.Equal(got, secondData) {
				t.Fatalf("second direction: %d bytes, %v", len(got), err)
			}
			r := waitRelay(t, res)
			if r.err != nil || r.up != int64(len(up)) || r.down != int64(len(down)) {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func TestRelayNoHalfClose(t *testing.T) {
	cli, cliSrv := net.Pipe()
	tgtSrv, tgt := net.Pipe()
	res := startRelay(new(server.Relayer), t.Context(), cliSrv, tgtSrv)
	go func() { _, _ = cli.Write([]byte("x")); cli.Close() }()
	expect(t, tgt, []byte("x"))
	if _, err := tgt.Read(make([]byte, 1)); err == nil {
		t.Fatal("target not closed")
	}
	if r := waitRelay(t, res); r.err != nil {
		t.Fatalf("%+v", r)
	}
}

func TestRelayErrors(t *testing.T) {
	t.Run("ctx", func(t *testing.T) {
		_, cliSrv := tcpPair(t)
		tgtSrv, _ := tcpPair(t)
		ctx, cancel := context.WithCancel(context.Background())
		res := startRelay(new(server.Relayer), ctx, cliSrv, tgtSrv)
		cancel()
		if r := waitRelay(t, res); !errors.Is(r.err, context.Canceled) {
			t.Fatal(r.err)
		}
	})
	t.Run("reset", func(t *testing.T) {
		cli, cliSrv := tcpPair(t)
		tgtSrv, tgt := tcpPair(t)
		res := startRelay(new(server.Relayer), t.Context(), cliSrv, tgtSrv)
		_ = cli.SetLinger(0)
		cli.Close()
		if r := waitRelay(t, res); r.err == nil {
			t.Fatal("reset not reported")
		}
		if _, err := tgt.Read(make([]byte, 1)); err == nil {
			t.Fatal("target left open")
		}
	})
	t.Run("idle", func(t *testing.T) {
		cli, cliSrv := tcpPair(t)
		tgtSrv, tgt := tcpPair(t)
		rl := &server.Relayer{IdleTimeout: 200 * time.Millisecond}
		start := time.Now()
		res := startRelay(rl, t.Context(), cliSrv, tgtSrv)
		for range 5 { // traffic one way keeps both alive
			_, _ = cli.Write([]byte("k"))
			expect(t, tgt, []byte("k"))
			time.Sleep(80 * time.Millisecond)
		}
		r := waitRelay(t, res)
		if !errors.Is(r.err, os.ErrDeadlineExceeded) || time.Since(start) < 450*time.Millisecond || r.up != 5 {
			t.Fatalf("%+v after %v", r, time.Since(start))
		}
	})
	t.Run("idle half-close", func(t *testing.T) {
		cli, cliSrv := tcpPair(t)
		tgtSrv, tgt := tcpPair(t)
		rl := &server.Relayer{IdleTimeout: 5 * time.Second, HalfCloseTimeout: 150 * time.Millisecond}
		res := startRelay(rl, t.Context(), cliSrv, tgtSrv)
		_, _ = cli.Write([]byte("bye"))
		_ = cli.CloseWrite()
		expect(t, tgt, []byte("bye"))
		start := time.Now()
		r := waitRelay(t, res)
		if d := time.Since(start); d > 2*time.Second || !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatalf("%+v after %v", r, d)
		}
	})
	t.Run("half-close timeout", func(t *testing.T) {
		cli, cliSrv := tcpPair(t)
		tgtSrv, _ := tcpPair(t)
		rl := &server.Relayer{HalfCloseTimeout: 150 * time.Millisecond, UserTimeout: -1}
		res := startRelay(rl, t.Context(), cliSrv, tgtSrv)
		_ = cli.CloseWrite()
		if r := waitRelay(t, res); !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatal(r.err)
		}
	})
}

type panicConn struct{ net.Conn }

func (panicConn) Write([]byte) (int, error) { panic("write panic") }

func TestRelayPanic(t *testing.T) {
	_, cliSrv := tcpPair(t)
	tgtSrv, tgt := tcpPair(t)
	_, _ = tgt.Write([]byte("x"))
	defer func() {
		if p := recover(); p != "write panic" {
			t.Fatalf("recovered %v", p)
		}
	}()
	_, _, _ = server.Relay(context.Background(), panicConn{cliSrv}, tgtSrv)
	t.Fatal("no panic")
}

// Conn.WriteTo/ReadFrom reach *net.TCPConn as splice recognizes it, after the buffered bytes.
func TestDelegation(t *testing.T) {
	for _, viaRelay := range []bool{false, true} {
		t.Run(fmt.Sprint("relay=", viaRelay), func(t *testing.T) {
			if viaRelay && !spliceOS() {
				t.Skip("Relay copies through buffers off Linux")
			}
			echo := echoTCP(t, "127.0.0.1:0")
			var target *spyConn
			s := open()
			s.Handler = server.HandlerFunc(func(ctx context.Context, r *server.Request) error {
				tc, err := net.Dial("tcp", echo)
				if err != nil {
					return err
				}
				target = &spyConn{TCPConn: tc.(*net.TCPConn)}
				c, err := r.Reply(0, wire.Addr{})
				if err != nil {
					return err
				}
				if viaRelay {
					_, _, err = server.Relay(ctx, c, target)
					return err
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					_, _ = io.Copy(c, target)
					_ = c.CloseWrite()
				}()
				_, _ = io.Copy(target, c)
				_ = target.CloseWrite()
				<-done
				return nil
			})
			ln := spyListener{listenLoopback(t), make(chan *spyConn, 1)}
			c := dial(t, serveLn(t, s, ln))
			_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, "192.0.2.1:80"), []byte("early")))
			client := <-ln.spies
			expect(t, c, []byte{5, 0})
			readReply(t, c, wire.CmdConnect)
			_, _ = c.Write([]byte("-later"))
			_ = c.CloseWrite()
			if got, err := io.ReadAll(c); string(got) != "early-later" || err != nil {
				t.Fatalf("echo %q, %v", got, err)
			}
			const wrapper = "ReadFrom net.tcpConnWithoutWriteTo" // what spliceFrom accepts
			waitFor(t, func() bool { return strings.Contains(client.got(), wrapper) && strings.Contains(target.got(), wrapper) })
			// up: buffered bytes, then TCPConn.WriteTo → target.ReadFrom.
			// down: target.WriteTo(*Conn) → Conn.ReadFrom → TCPConn.ReadFrom,
			// on another goroutine, so it may be logged first: ignored.
			got := target.got()
			up := strings.ReplaceAll(strings.ReplaceAll(got, "WriteTo *server.Conn; ", ""), "; WriteTo *server.Conn", "")
			if !strings.HasPrefix(up, `Write "early"; `) || !strings.Contains(got, "WriteTo *server.Conn") {
				t.Errorf("target: %s", got)
			}
			if got := client.got(); !strings.Contains(got, "WriteTo *server_test.spyConn") || !strings.Contains(got, wrapper) {
				t.Errorf("client: %s", got)
			}
		})
	}
}

// Concurrent tunnels (splice on Linux) never see each other's bytes.
func TestRelayNoCrossTalk(t *testing.T) {
	target := echoTCP(t, "127.0.0.1:0")
	proxy := serve(t, open())
	const conns, par = 400, 64
	var wg sync.WaitGroup
	sem := make(chan struct{}, par)
	for id := range conns {
		wg.Go(func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			mark := fmt.Appendf(nil, "<conn %04d>", id)
			early := bytes.Repeat(mark, 1+id%250)
			rest := bytes.Repeat(mark, 1+(id*37)%9000)
			c, err := net.Dial("tcp", proxy)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(20 * time.Second))
			go func() {
				_, _ = c.Write(cat(greeting(0), request(wire.CmdConnect, target), early))
				_, _ = c.Write(rest)
				_ = c.(*net.TCPConn).CloseWrite()
			}()
			got, err := io.ReadAll(c)
			if err != nil || len(got) < 2+10 || !bytes.Equal(got[:2], []byte{5, 0}) || !bytes.Equal(got[12:], cat(early, rest)) {
				t.Errorf("conn %d: %d bytes, %v", id, len(got), err)
			}
		})
	}
	wg.Wait()
}
