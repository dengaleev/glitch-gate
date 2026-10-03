package clients

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// anyTarget is a CONNECT target; the in-process server ignores it.
const anyTarget = "127.0.0.1:7"

var aLongTimeAgo = time.Unix(1, 0)

// Once dials target through proxy and echoes payload. It returns the time
// from the start of Dial to the last echoed byte.
func Once(ctx context.Context, c Client, proxy, user, pass, target string, payload []byte) (time.Duration, error) {
	start := time.Now()
	conn, err := dial(ctx, c, proxy, user, pass, target)
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(aLongTimeAgo) })
	defer stop()

	// Write while reading: large echoes must drain, and an early-data client
	// learns the handshake's fate on Read.
	written := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		written <- err
	}()
	got := make([]byte, len(payload))
	_, err = io.ReadFull(conn, got)
	elapsed := time.Since(start)
	if err == nil {
		err = <-written
	}
	if err != nil {
		if ctx.Err() != nil {
			err = ctx.Err() // our forced deadline, not the network's
		}
		return 0, fmt.Errorf("echo: %w", err)
	}
	if !bytes.Equal(got, payload) {
		return 0, errors.New("echo: payload mismatch")
	}
	return elapsed, nil
}

// dial bounds c.Dial by ctx even when the library ignores ctx in the handshake
// (txthinking; gost and outline only for TCP). A timed-out dial is abandoned
// and its conn closed when it arrives.
func dial(ctx context.Context, c Client, proxy, user, pass, target string) (net.Conn, error) {
	if ctx.Done() == nil { // uncancelable: keep the goroutine out of Allocs
		return c.Dial(ctx, proxy, user, pass, target)
	}
	type result struct {
		conn net.Conn
		err  error
	}
	done := make(chan result, 1)
	go func() {
		conn, err := c.Dial(ctx, proxy, user, pass, target)
		done <- result{conn, err}
	}()
	select {
	case r := <-done:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-done; r.conn != nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// EarlyData reports whether c sends data before the CONNECT reply (L2), using
// a server that withholds the reply for up to 200ms.
func EarlyData(ctx context.Context, c Client, user, pass string) (bool, error) {
	early := make(chan bool, 1)
	addr, stop, err := (&server{
		user: user, pass: pass,
		hold:    200 * time.Millisecond,
		onReply: func(st connStats) { early <- st.early },
	}).listen()
	if err != nil {
		return false, err
	}
	defer stop()
	if _, err := Once(ctx, c, addr, user, pass, anyTarget, []byte("early?")); err != nil {
		return false, err
	}
	return <-early, nil
}

// Allocs reports heap allocations per dial + 1-byte echo through an in-process
// server. The server's share is a constant offset across clients. It uses
// context.Background: x/net spends a goroutine on a cancelable ctx.
func Allocs(c Client, user, pass string) (float64, error) {
	var err error
	r := testing.Benchmark(func(b *testing.B) {
		if err = bench(b, c, user, pass); err != nil {
			b.FailNow()
		}
	})
	if err != nil {
		return 0, err
	}
	return float64(r.MemAllocs) / float64(r.N), nil
}

func bench(b *testing.B, c Client, user, pass string) error {
	addr, stop, err := (&server{user: user, pass: pass}).listen()
	if err != nil {
		return err
	}
	defer stop()
	ctx, payload := context.Background(), []byte{'x'}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Once(ctx, c, addr, user, pass, anyTarget, payload); err != nil {
			return err
		}
	}
	return nil
}
