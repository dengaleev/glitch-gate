package socks0

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

// Mode is how the handshake is put on the wire; there is no fallback between modes.
type Mode uint8

const (
	// ModePipelined (L1, the zero value) sends greeting, auth and request in one write.
	ModePipelined Mode = iota

	// ModeSequential (L0) waits for each server message; interactive authenticators need it.
	ModeSequential

	// ModeEarly (L2) sends the handshake with the first Write's data. DialContext
	// returns before the CONNECT, so probes must not use it. A Read before the
	// first Write waits for one: server-first protocols must call HandshakeContext.
	ModeEarly
)

func (m Mode) String() string {
	switch m {
	case ModePipelined:
		return "pipelined"
	case ModeSequential:
		return "sequential"
	case ModeEarly:
		return "early"
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

// Config configures a client; nil is the zero Config. Do not modify it once in use.
type Config struct {
	// Version is 0 or 5 (SOCKS5), or 4 (SOCKS4, or 4a for names). SOCKS4 has no
	// UDP or RESOLVE (errors.ErrUnsupported) and no IPv6; its Auth is nil or a
	// UserPass without Password (the USERID).
	Version uint8

	Mode Mode

	// Auth is the only method offered (nil: MethodNoAuth); ModePipelined and
	// ModeEarly need a Pipeliner, else ErrNotPipelinable. They send RFC 1929
	// credentials in cleartext before the proxy speaks: over untrusted networks
	// use TLS (socks5s://) or ModeSequential.
	Auth Authenticator

	// OfferNoAuth also offers MethodNoAuth, skipping Auth if selected; SOCKS5 and
	// ModeSequential only.
	OfferNoAuth bool

	// ReplyTimeout (ModeEarly) bounds a call's wait for the replies, narrowing the
	// read deadline; expiry is sticky os.ErrDeadlineExceeded. Zero means
	// HandshakeTimeout, which it overrides.
	ReplyTimeout time.Duration

	// HandshakeTimeout bounds each handshake (a Dialer's: proxy dial to reply).
	// Zero is 30 s unless ctx has a deadline; positive applies always, earliest
	// wins; negative is none. Expiry is sticky, wrapping context.DeadlineExceeded.
	// It does not bound Listener.Accept; in ModeEarly set deadlines on the *Conn.
	HandshakeTimeout time.Duration

	// Trace hooks run before those of WithClientTrace.
	Trace *ClientTrace
}

// Authenticator is a SOCKS5 method; it must not read past its subnegotiation.
type Authenticator interface {
	Method() wire.Method

	// Authenticate runs in ModeSequential; the caller unblocks rw on cancellation.
	// A rejection should match ErrAuthFailed.
	Authenticate(ctx context.Context, rw io.ReadWriter) error
}

// Pipeliner is a one-request, one-reply Authenticator, required by
// ModePipelined and ModeEarly.
type Pipeliner interface {
	Authenticator

	// AppendRequest is called before connecting.
	AppendRequest(dst []byte) ([]byte, error)

	// ParseReply follows the wire Parse contract (wire.ErrIncomplete with the
	// length needed); a rejection matches ErrAuthFailed.
	ParseReply(b []byte) (n int, err error)
}

// UserPass is RFC 1929 auth, 0–255 bytes each, sent in cleartext. fmt, slog and
// errors show the password as "[redacted]", also inside Config and ProxyURL;
// handshake buffers are zeroed after the write (best effort).
type UserPass struct {
	Username string
	Password string
}

const redacted = "[redacted]"

func redact(s string) string {
	if s == "" {
		return ""
	}
	return redacted
}

func (a UserPass) String() string { return "{" + a.Username + " " + redact(a.Password) + "}" }

func (a UserPass) GoString() string {
	return "socks0.UserPass{Username:" + strconv.Quote(a.Username) + ", Password:" + strconv.Quote(redact(a.Password)) + "}"
}

func (a UserPass) Format(f fmt.State, verb rune) {
	if verb == 'v' && f.Flag('#') {
		_, _ = io.WriteString(f, a.GoString())
		return
	}
	_, _ = io.WriteString(f, a.String())
}

func (a UserPass) LogValue() slog.Value {
	return slog.GroupValue(slog.String("username", a.Username), slog.String("password", redact(a.Password)))
}

func (c Config) LogValue() slog.Value {
	attrs := []slog.Attr{slog.Int("version", int(c.Version)), slog.String("mode", c.Mode.String())}
	if c.Auth != nil {
		if lv, ok := c.Auth.(slog.LogValuer); ok {
			attrs = append(attrs, slog.Any("auth", lv))
		} else {
			attrs = append(attrs, slog.String("auth", c.Auth.Method().String()))
		}
	}
	return slog.GroupValue(append(attrs,
		slog.Bool("offer_noauth", c.OfferNoAuth),
		slog.Duration("reply_timeout", c.ReplyTimeout),
		slog.Duration("handshake_timeout", c.HandshakeTimeout))...)
}

func (UserPass) Method() wire.Method { return wire.MethodUserPass }

func (a UserPass) Authenticate(ctx context.Context, rw io.ReadWriter) error {
	b, err := a.AppendRequest(nil)
	if err != nil {
		return err
	}
	_, err = rw.Write(b)
	clear(b)
	if err != nil {
		return err
	}
	status, err := wire.ReadUserPassStatus(rw)
	return statusErr(status, err)
}

func (a UserPass) AppendRequest(dst []byte) ([]byte, error) {
	return wire.AppendUserPass(dst, a.Username, a.Password)
}

// ParseReply returns an *AuthError for a non-zero status.
func (a UserPass) ParseReply(b []byte) (int, error) {
	status, n, err := wire.ParseUserPassStatus(b)
	return n, statusErr(status, err)
}

func statusErr(status uint8, err error) error {
	if err == nil && status != 0 {
		return &AuthError{Method: wire.MethodUserPass, Status: status}
	}
	return err
}
