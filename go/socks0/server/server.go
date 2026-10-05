package server

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Version is a set of protocol versions; Request.Version holds exactly one.
type Version uint8

const (
	V4 Version = 1 << iota // SOCKS4 and SOCKS4a
	V5                     // SOCKS5
)

func (v Version) String() string {
	var s []string
	if v&V4 != 0 {
		s = append(s, "socks4")
	}
	if v&V5 != 0 {
		s = append(s, "socks5")
	}
	if rest := v &^ (V4 | V5); rest != 0 || v == 0 {
		s = append(s, fmt.Sprintf("Version(0x%02x)", uint8(rest)))
	}
	return strings.Join(s, "|")
}

type ConnState uint8

const (
	StateNew    ConnState = iota // in the handshake; Shutdown closes it
	StateActive                  // Handler running, no successful reply yet
	StateTunnel                  // replied success: relaying
	StateClosed                  // final

	stateShut // StateNew closed by Shutdown or Close
)

func (s ConnState) String() string {
	switch s {
	case StateNew:
		return "new"
	case StateActive:
		return "active"
	case StateTunnel:
		return "tunnel"
	case StateClosed:
		return "closed"
	}
	return fmt.Sprintf("ConnState(%d)", uint8(s))
}

// Server is a SOCKS server. The zero Server is an open proxy to public addresses: listen on
// loopback or set Auth. Fields must not change after the first Serve or ServeConn.
type Server struct {
	// Addr defaults to "localhost:1080".
	Addr string

	// Versions defaults to V5; any other first byte closes the conn without a reply.
	Versions Version

	// Auth is in preference order; nil means NoAuth. Duplicates, nil or MethodNoAcceptable are errors.
	Auth []Authenticator

	// UserID authorizes SOCKS4 (userID aliases the read buffer; Method becomes MethodUserPass). nil
	// admits SOCKS4 only if Auth holds the built-in NoAuth, so V4 cannot bypass SOCKS5 authentication.
	UserID func(ctx context.Context, userID []byte) (identity any, err error)

	// Handler defaults to &Mux{Connect: &ConnectHandler{}}.
	Handler Handler

	// Allow vets requests by the target as sent, after auth; an error is replied as ReplyFor(err).
	Allow func(ctx context.Context, r *Request) error

	// Admit runs before any byte is read; an error closes the conn unanswered. release runs at close.
	Admit func(ctx context.Context, c net.Conn) (release func(), err error)

	// HandshakeTimeout is one absolute deadline from accept through the request, also bounding
	// each reply write. Zero means 10 s; negative, none.
	HandshakeTimeout time.Duration

	// MaxConns caps conns across listeners; at the cap Serve stops accepting (ServeConn is never
	// refused). Zero means no cap: set one on a public server.
	MaxConns int

	// MaxHandshakes caps conns in StateNew, closing new ones over it. Zero means 1024; negative, none.
	MaxHandshakes int

	// SelfAddrs are this host's addresses on no interface (1:1 NAT, load balancer VIP); DefaultFilter
	// denies them in every encoding so the server cannot loop into itself.
	SelfAddrs []netip.Prefix

	// BaseContext and ConnContext are as in http.Server; a conn is closed when its ctx is done.
	BaseContext func(net.Listener) context.Context
	ConnContext func(ctx context.Context, c net.Conn) context.Context

	ConnState func(net.Conn, ConnState)

	Trace *ServerTrace

	// ErrorLog logs accept errors and recovered panics only; nil means the log package's logger.
	ErrorLog *log.Logger

	once   sync.Once
	cfg    config
	cfgErr error

	mu          sync.Mutex
	done        chan struct{} // closed by Shutdown and Close, under mu
	listeners   map[*net.Listener]struct{}
	conns       map[*serverConn]struct{}
	onShutdown  []func()
	slotsUsed   int           // toward MaxConns
	slotFreed   chan struct{} // closed when a conn ends while a Serve loop waits for a slot
	inHandshake atomic.Int64  // conns in StateNew
}

type config struct {
	versions         Version
	auth             []Authenticator
	builtinNoAuth    bool
	handler          Handler
	handshakeTimeout time.Duration // 0: none
	maxHandshakes    int64         // 0: none
	selfAddrs        []netip.Prefix
}

const (
	defaultAddr             = "localhost:1080"
	defaultHandshakeTimeout = 10 * time.Second
	defaultMaxHandshakes    = 1024
)

func (s *Server) init() error {
	s.once.Do(func() {
		s.done = make(chan struct{})
		s.listeners = make(map[*net.Listener]struct{})
		s.conns = make(map[*serverConn]struct{})
		if err := s.configure(); err != nil {
			s.cfgErr = &socks0.HandshakeError{Stage: socks0.StageConfig, Err: err}
		}
	})
	return s.cfgErr
}

func (s *Server) configure() error {
	if s.Versions&^(V4|V5) != 0 {
		return fmt.Errorf("socks0/server: unknown Versions %v", s.Versions)
	}
	c := &s.cfg
	c.versions = cmp.Or(s.Versions, V5)
	var err error
	if c.auth, c.builtinNoAuth, err = authMethods(s.Auth); err != nil {
		return err
	}
	c.handler = s.Handler
	if c.handler == nil {
		c.handler = &Mux{Connect: &ConnectHandler{}}
	}
	if err := validate(c.handler); err != nil {
		return err
	}
	c.handshakeTimeout = orDefault(s.HandshakeTimeout, defaultHandshakeTimeout)
	c.maxHandshakes = int64(orDefault(s.MaxHandshakes, defaultMaxHandshakes))
	c.selfAddrs, err = selfPrefixes(s.SelfAddrs)
	return err
}

// authMethods: a custom method 00 is not builtinNoAuth, as SOCKS4 would skip its checks.
func authMethods(auth []Authenticator) (_ []Authenticator, builtinNoAuth bool, err error) {
	auth = slices.Clone(auth)
	if auth == nil {
		auth = []Authenticator{NoAuth{}}
	}
	var seen [256]bool
	for _, a := range auth {
		if a == nil {
			return nil, false, errors.New("socks0/server: nil Authenticator in Auth")
		}
		m := a.Method()
		switch {
		case m == wire.MethodNoAcceptable:
			return nil, false, errors.New("socks0/server: Authenticator with MethodNoAcceptable")
		case seen[m]:
			return nil, false, fmt.Errorf("socks0/server: method %v twice in Auth", m)
		}
		seen[m] = true
		switch a.(type) {
		case NoAuth, *NoAuth:
			builtinNoAuth = true
		}
	}
	return auth, builtinNoAuth, nil
}

func selfPrefixes(addrs []netip.Prefix) ([]netip.Prefix, error) {
	var self []netip.Prefix
	for _, p := range addrs {
		if !p.IsValid() {
			return nil, fmt.Errorf("socks0/server: invalid prefix %v in SelfAddrs", p)
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		self = append(self, p.Masked())
	}
	return self, nil
}

// validate checks a built-in handler's config (a *Mux's entries too); behind another Handler the
// built-in checks itself per request.
func validate(h Handler) error {
	if v, ok := h.(interface{ validate() error }); ok {
		return v.validate()
	}
	return nil
}

// orDefault: zero means def, negative none (0).
func orDefault[T ~int | ~int64](v, def T) T { return max(cmp.Or(v, def), 0) }

func (c *config) choose(offered []wire.Method) Authenticator {
	for _, a := range c.auth {
		if slices.Contains(offered, a.Method()) {
			return a
		}
	}
	return nil
}

// ListenAndServe listens with net.ListenConfig's keep-alive defaults.
func (s *Server) ListenAndServe() error {
	if s.shuttingDown() {
		return ErrServerClosed
	}
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", cmp.Or(s.Addr, defaultAddr))
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve closes ln when it returns and always returns a non-nil error, ErrServerClosed after
// Shutdown or Close. It backs off on net.Error accept errors (5 ms to 1 s).
func (s *Server) Serve(ln net.Listener) error {
	if err := s.init(); err != nil {
		ln.Close()
		return err
	}
	if !s.addListener(&ln) {
		ln.Close()
		return ErrServerClosed
	}
	defer s.removeListener(&ln)
	defer ln.Close()

	base := context.Background()
	if s.BaseContext != nil {
		base = cmp.Or(s.BaseContext(ln), base)
	}
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if delay, err = s.acceptBackoff(err, delay); err != nil {
				return err
			}
			continue
		}
		delay = 0
		if err := s.start(base, c); err != nil {
			return err
		}
	}
}

func (s *Server) acceptBackoff(err error, delay time.Duration) (time.Duration, error) {
	if s.shuttingDown() {
		return 0, ErrServerClosed
	}
	if _, ok := errors.AsType[net.Error](err); !ok || errors.Is(err, net.ErrClosed) {
		return 0, err
	}
	delay = min(max(2*delay, 5*time.Millisecond), time.Second)
	s.logf("socks0/server: accept error: %q; retrying in %v", err.Error(), delay)
	select {
	case <-time.After(delay):
		return delay, nil
	case <-s.done:
		return 0, ErrServerClosed
	}
}

func (s *Server) start(base context.Context, c net.Conn) error {
	if mh := s.cfg.maxHandshakes; mh > 0 && s.inHandshake.Load() >= mh {
		c.Close()
		return nil
	}
	if err := s.waitSlot(); err != nil {
		c.Close()
		return err
	}
	sc := s.newConn(s.connContext(base, c), c, true)
	if sc == nil {
		c.Close()
		return ErrServerClosed
	}
	go sc.serve()
	return nil
}

// waitSlot: every conn end wakes all waiting loops, which recount under s.mu.
func (s *Server) waitSlot() error {
	s.mu.Lock()
	for {
		switch {
		case closed(s.done):
			s.mu.Unlock()
			return ErrServerClosed
		case s.MaxConns <= 0 || s.slotsUsed < s.MaxConns:
			s.slotsUsed++
			s.mu.Unlock()
			return nil
		}
		if s.slotFreed == nil {
			s.slotFreed = make(chan struct{})
		}
		freed := s.slotFreed
		s.mu.Unlock()
		select {
		case <-freed:
		case <-s.done:
		}
		s.mu.Lock()
	}
}

// ServeConn serves c on the caller's goroutine and closes it, also when ctx is done; Shutdown and
// Close track it. It returns nil if the handler replied and returned nil, the handler's or Admit's
// error (ErrNoReply if none replied), ErrServerClosed, a config *socks0.HandshakeError, or for a
// handshake failure a *net.OpError wrapping a *socks0.HandshakeError naming the Stage.
func (s *Server) ServeConn(ctx context.Context, c net.Conn) error {
	if err := s.init(); err != nil {
		c.Close()
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	sc := s.newConn(s.connContext(ctx, c), c, false)
	if sc == nil {
		c.Close()
		return ErrServerClosed
	}
	return sc.serve()
}

func (s *Server) connContext(ctx context.Context, c net.Conn) context.Context {
	if s.ConnContext != nil {
		return s.ConnContext(ctx, c)
	}
	return ctx
}

// Shutdown closes the listeners and the conns in StateNew, then waits for the rest or ctx.
// Tunnels are not cut, as in http.Server.
func (s *Server) Shutdown(ctx context.Context) error {
	lnErr := s.stop(true)
	wait := time.Millisecond
	t := time.NewTimer(wait)
	defer t.Stop()
	for {
		if s.closeHandshakes() == 0 {
			return lnErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			wait = min(2*wait, 100*time.Millisecond)
			t.Reset(wait)
		}
	}
}

// Close closes the listeners and every conn and cancels every handler ctx, without waiting.
func (s *Server) Close() error {
	err := s.stop(false)
	s.mu.Lock()
	defer s.mu.Unlock()
	for sc := range s.conns {
		sc.state.CompareAndSwap(uint32(StateNew), uint32(stateShut))
		sc.cancel()
		sc.nc.Close()
	}
	return err
}

func (s *Server) stop(runHooks bool) error {
	_ = s.init()
	s.mu.Lock()
	if !closed(s.done) {
		close(s.done)
		if runHooks {
			for _, f := range s.onShutdown {
				go f()
			}
		}
	}
	lns := make([]net.Listener, 0, len(s.listeners))
	for ln := range s.listeners {
		lns = append(lns, *ln)
	}
	s.mu.Unlock()
	var errs []error
	for _, ln := range lns {
		if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Server) closeHandshakes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sc := range s.conns {
		if sc.state.CompareAndSwap(uint32(StateNew), uint32(stateShut)) {
			sc.nc.Close()
		}
	}
	return len(s.conns)
}

// RegisterOnShutdown runs f on its own goroutine when Shutdown starts.
func (s *Server) RegisterOnShutdown(f func()) {
	_ = s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onShutdown = append(s.onShutdown, f)
}

func (s *Server) shuttingDown() bool {
	_ = s.init()
	return closed(s.done)
}

func closed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func (s *Server) addListener(ln *net.Listener) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed(s.done) {
		return false
	}
	s.listeners[ln] = struct{}{}
	return true
}

func (s *Server) removeListener(ln *net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.listeners, ln)
}

// newConn returns nil after Shutdown; slotTaken means waitSlot already counted the conn.
func (s *Server) newConn(ctx context.Context, c net.Conn, slotTaken bool) *serverConn {
	sc := &serverConn{s: s, nc: c, parent: ctx}
	sc.ctx, sc.cancel = context.WithCancel(ctx)
	sc.req.sc, sc.conn.sc, sc.auth.sc = sc, sc, sc
	s.mu.Lock()
	defer s.mu.Unlock()
	if closed(s.done) {
		if slotTaken {
			s.slotsUsed--
		}
		sc.cancel()
		return nil
	}
	s.conns[sc] = struct{}{}
	if !slotTaken {
		s.slotsUsed++
	}
	s.inHandshake.Add(1)
	return sc
}

func (s *Server) untrack(sc *serverConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, sc)
	s.slotsUsed--
	if s.slotFreed != nil {
		close(s.slotFreed)
		s.slotFreed = nil
	}
}

func (s *Server) setState(c net.Conn, st ConnState) {
	if s.ConnState != nil {
		s.ConnState(c, st)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
