package server

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Relayer copies between a client and a target; the zero Relayer is ready.
type Relayer struct {
	// IdleTimeout closes both conns after no byte moved either way this long; it rules out splice
	// (pooled 32 KiB buffers are used). Zero means none.
	IdleTimeout time.Duration

	// HalfCloseTimeout bounds the remaining direction after the other ended with EOF; zero means none.
	HalfCloseTimeout time.Duration

	// UserTimeout sets Linux TCP_USER_TIMEOUT (splice kept). Zero means 2 min; negative, untouched.
	UserTimeout time.Duration
}

// Relay is (&Relayer{}).Relay.
func Relay(ctx context.Context, client, target net.Conn) (up, down int64, err error) {
	var rl Relayer
	return rl.Relay(ctx, client, target)
}

// Relay copies both ways on the caller's goroutine plus one more until both directions end: EOF
// half-closes the other side (or closes both), an error or ctx closes both. A *Conn's buffered
// bytes go first; Linux TCP↔TCP splices. err is nil if both ended in EOF, else the first error.
// Both conns are closed on return; a panic on the second goroutine is re-raised on the caller's.
func (rl *Relayer) Relay(ctx context.Context, client, target net.Conn) (up, down int64, err error) {
	if ut := orDefault(rl.UserTimeout, defaultUserTimeout); ut > 0 {
		setUserTimeout(client, ut)
		setUserTimeout(target, ut)
	}
	st := &relayState{rl: *rl, client: client, target: target}
	st.upW.Writer, st.upR.Reader, st.downW.Writer, st.downR.Reader = target, client, client, target
	st.lastMove.Store(time.Now().UnixNano())
	stop := func() bool { return true }
	if !isHandlerCtx(ctx, client) && ctx.Done() != nil { // Done would allocate the handler ctx's channel
		stop = context.AfterFunc(ctx, func() { st.fail(ctx.Err()) })
	}
	st.wg.Add(1)
	go st.runDown() // not wg.Go: one closure fewer per tunnel
	up = st.copy(target, client, &st.upW, &st.upR)
	st.wg.Wait()
	stop()
	st.once.Do(func() {}) // synchronizes with fail: st.err is final
	client.Close()
	target.Close()
	if st.panicked != nil {
		panic(st.panicked)
	}
	if err = st.err; err != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	return up, st.down, err
}

// isHandlerCtx: canceling client's handler ctx already closes client, ending both directions.
func isHandlerCtx(ctx context.Context, client net.Conn) bool {
	cc, ok := client.(*Conn)
	return ok && ctx == cc.sc.ctx
}

var errPanic = errors.New("socks0/server: relay panicked")

const defaultUserTimeout = 2 * time.Minute

type relayState struct {
	rl             Relayer // a copy: rl does not escape
	client, target net.Conn
	lastMove       atomic.Int64 // UnixNano
	halfCloseAt    atomic.Int64 // UnixNano deadline once one direction ended
	wg             sync.WaitGroup
	down           int64
	panicked       any

	// Pointers to these convert to interfaces without allocating.
	upW, downW writerOnly
	upR, downR readerOnly

	once sync.Once
	err  error
}

func (st *relayState) runDown() {
	defer st.wg.Done()
	defer func() {
		if st.panicked = recover(); st.panicked != nil {
			st.fail(errPanic)
		}
	}()
	st.down = st.copy(st.client, st.target, &st.downW, &st.downR)
}

func (st *relayState) fail(err error) {
	st.once.Do(func() { st.err = err })
	st.client.Close()
	st.target.Close()
}

func (st *relayState) copy(dst, src net.Conn, w *writerOnly, r *readerOnly) int64 {
	var n int64
	var err error
	switch {
	case st.rl.IdleTimeout > 0:
		n, err = st.copyIdle(dst, src)
	case runtime.GOOS == "linux":
		n, err = io.Copy(dst, src)
	default:
		b := copyBufs.Get().(*[]byte)
		n, err = io.CopyBuffer(w, r, *b)
		copyBufs.Put(b)
	}
	if err != nil {
		st.fail(err)
		return n
	}
	if hc := st.rl.HalfCloseTimeout; hc > 0 {
		d := time.Now().Add(hc)
		st.halfCloseAt.CompareAndSwap(0, d.UnixNano())
		_ = st.client.SetDeadline(d)
		_ = st.target.SetDeadline(d)
	}
	if cw, ok := dst.(closeWriter); !ok || cw.CloseWrite() != nil {
		st.fail(nil)
	}
	return n
}

var copyBufs = sync.Pool{New: func() any { return new(make([]byte, 32<<10)) }}

func (st *relayState) copyIdle(dst, src net.Conn) (n int64, err error) {
	b := copyBufs.Get().(*[]byte)
	defer copyBufs.Put(b)
	idle := st.rl.IdleTimeout
	for arm := true; ; {
		if arm {
			_ = src.SetReadDeadline(st.readDeadline())
		}
		m, rerr := src.Read(*b)
		if m > 0 {
			now := time.Now()
			st.lastMove.Store(now.UnixNano())
			_ = dst.SetWriteDeadline(now.Add(idle))
			w, werr := dst.Write((*b)[:m])
			n += int64(w)
			if werr != nil {
				return n, werr
			}
		}
		// A deadline armed earlier fires early if bytes moved since: otherDirectionMoved re-arms it.
		// Once half-closed, every read re-arms, as halfCloseAt replaced the idle deadline.
		switch {
		case rerr == nil:
			arm = st.halfCloseAt.Load() != 0
		case st.otherDirectionMoved(rerr):
			arm = true
		case errors.Is(rerr, io.EOF):
			return n, nil
		default:
			return n, rerr
		}
	}
}

func (st *relayState) readDeadline() time.Time {
	d := time.Unix(0, st.lastMove.Load()).Add(st.rl.IdleTimeout)
	if hc := st.halfCloseAt.Load(); hc != 0 && hc < d.UnixNano() {
		return time.Unix(0, hc)
	}
	return d
}

// otherDirectionMoved: a read timeout is not idleness if the other direction moved meanwhile.
func (st *relayState) otherDirectionMoved(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded) &&
		time.Since(time.Unix(0, st.lastMove.Load())) < st.rl.IdleTimeout &&
		st.halfCloseAt.Load() == 0
}
