// Package servers adapts Go SOCKS5 server libraries to one interface and
// checks whether each is ready for pipelined (L1) and early-data (L2) clients.
package servers

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"

	armon "github.com/armon/go-socks5"
	lantern "github.com/getlantern/go-socks5"
	"github.com/getlantern/golog"
	haxii "github.com/haxii/socks5"
	"github.com/sagernet/sing/common/auth"
	singbufio "github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	thingsgo "github.com/things-go/go-socks5"
	txthinking "github.com/txthinking/socks5"
	wzshiming "github.com/wzshiming/socks5"
)

// Server is a SOCKS5 server library under test.
type Server struct {
	Name     string
	UserPass bool // supports RFC 1929 auth
	// Serve serves on ln until it is closed; an empty user means no auth.
	Serve func(ln net.Listener, user, pass string) error
}

var quietLog = log.New(io.Discard, "", 0)

// All lists every server under test, in report order.
var All = []Server{
	{Name: "armon/go-socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		conf := &armon.Config{Logger: quietLog}
		if user != "" {
			conf.Credentials = armon.StaticCredentials{user: pass}
		}
		s, err := armon.New(conf)
		if err != nil {
			return err
		}
		return s.Serve(ln)
	}},
	{Name: "things-go/go-socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		opts := []thingsgo.Option{thingsgo.WithLogger(thingsgo.NewLogger(quietLog))}
		if user != "" {
			opts = append(opts, thingsgo.WithCredential(thingsgo.StaticCredentials{user: pass}))
		}
		return thingsgo.NewServer(opts...).Serve(ln)
	}},
	{Name: "txthinking/socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		// ListenAndServe opens its own listeners; this is its accept loop
		// body on ln, minus logging.
		s, err := txthinking.NewClassicServer(ln.Addr().String(), "127.0.0.1", user, pass, 0, 0)
		if err != nil {
			return err
		}
		s.Handle = &txthinking.DefaultHandle{}
		return serveEach(ln, func(c net.Conn) {
			if s.Negotiate(c) != nil {
				return
			}
			r, err := s.GetRequest(c)
			if err != nil {
				return
			}
			_ = s.Handle.TCPHandle(s, c.(*net.TCPConn), r)
		})
	}},
	{Name: "wzshiming/socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		s := wzshiming.NewServer() // nil Logger is silent
		if user != "" {
			s.Authentication = wzshiming.UserAuth(user, pass)
		}
		return s.Serve(ln)
	}},
	{Name: "haxii/socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		conf := &haxii.Config{Logger: quietLog}
		if user != "" {
			conf.Credentials = haxii.StaticCredentials{user: pass}
		}
		s, err := haxii.New(conf)
		if err != nil {
			return err
		}
		return s.Serve(ln)
	}},
	{Name: "getlantern/go-socks5", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		golog.SetOutputs(io.Discard, io.Discard) // the library's package-level logger
		conf := &lantern.Config{}
		if user != "" {
			conf.Credentials = lantern.StaticCredentials{user: pass}
		}
		s, err := lantern.New(conf)
		if err != nil {
			return err
		}
		return s.Serve(ln)
	}},
	{Name: "sagernet/sing", UserPass: true, Serve: func(ln net.Listener, user, pass string) error {
		var au *auth.Authenticator
		if user != "" {
			au = auth.NewAuthenticator([]auth.User{{Username: user, Password: pass}})
		}
		// sing has no server loop; this mirrors sing-box's socks inbound.
		return serveEach(ln, func(c net.Conn) {
			_ = socks.HandleConnectionEx(context.Background(), c, bufio.NewReader(c), au,
				singRelay{}, nil, 0, M.SocksaddrFromNet(c.RemoteAddr()), nil)
		})
	}},
}

// serveEach runs handle on each conn accepted from ln in its own goroutine,
// then closes the conn.
func serveEach(ln net.Listener, handle func(net.Conn)) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer c.Close()
			handle(c)
		}()
	}
}

// singRelay stands in for sing-box's ConnectionManager: dial, report success
// (which writes the CONNECT reply), copy.
type singRelay struct{}

func (singRelay) NewConnectionEx(ctx context.Context, conn net.Conn, _, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	target, err := net.Dial("tcp", dst.String())
	if err != nil {
		_ = N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	defer target.Close()
	if N.ReportConnHandshakeSuccess(conn, target) != nil {
		return
	}
	_ = singbufio.CopyConn(ctx, conn, target)
}

func (singRelay) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	_ = conn.Close() // UDP ASSOCIATE is out of scope
}
