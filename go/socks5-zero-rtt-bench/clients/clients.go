// Package clients adapts Go SOCKS5 client libraries to one interface, plus
// reference clients that pipeline the handshake (L1) and send early data (L2).
package clients

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/go-gost/gosocks5"
	gostclient "github.com/go-gost/gosocks5/client"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
	txsocks5 "github.com/txthinking/socks5"
	wzsocks5 "github.com/wzshiming/socks5"
	"golang.getoutline.org/sdk/transport"
	outline "golang.getoutline.org/sdk/transport/socks5"
	"golang.org/x/net/proxy"
)

// Client is a SOCKS5 client library under test.
type Client struct {
	Name string
	// Dial opens a CONNECT tunnel to target via proxy; empty user: no auth.
	Dial func(ctx context.Context, proxy, user, pass, target string) (net.Conn, error)
}

// All lists the clients in report order, reference clients last.
var All = []Client{
	{"x/net/proxy", xnet},
	{"txthinking/socks5", txthinking},
	{"wzshiming/socks5", wzshiming},
	{"go-gost/gosocks5", gost},
	{"sagernet/sing", sing},
	{"outline-sdk", outlineSDK},
	{"ref L1", refL1},
	{"ref L1+L2", refL1L2},
}

func xnet(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	var auth *proxy.Auth
	if user != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	d, err := proxy.SOCKS5("tcp", addr, auth, nil)
	if err != nil {
		return nil, err
	}
	return d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
}

// txthinking ignores ctx.
func txthinking(_ context.Context, addr, user, pass, target string) (net.Conn, error) {
	c, err := txsocks5.NewClient(addr, user, pass, 0, 0)
	if err != nil {
		return nil, err
	}
	return c.Dial("tcp", target)
}

func wzshiming(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	d, err := wzsocks5.NewDialer("socks5h://" + addr)
	if err != nil {
		return nil, err
	}
	d.Username, d.Password = user, pass
	return d.DialContext(ctx, "tcp", target)
}

// gost's client only negotiates the method (and auth); CONNECT is ours to
// send, as in its README. ctx covers the TCP connect only.
func gost(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	var opts []gostclient.DialOption
	if user != "" {
		sel := gostclient.NewClientSelector(url.UserPassword(user, pass), gosocks5.MethodUserPass)
		opts = append(opts, gostclient.SelectorDialOption(sel))
	}
	dst, err := gosocks5.NewAddr(target)
	if err != nil {
		return nil, err
	}
	conn, err := gostclient.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, err
	}
	if err := gostConnect(conn, dst); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func gostConnect(rw io.ReadWriter, dst *gosocks5.Addr) error {
	if err := gosocks5.NewRequest(gosocks5.CmdConnect, dst).Write(rw); err != nil {
		return err
	}
	rep, err := gosocks5.ReadReply(rw)
	if err != nil {
		return err
	}
	if rep.Rep != gosocks5.Succeeded {
		return fmt.Errorf("gosocks5: connect rejected (rep 0x%02x)", rep.Rep)
	}
	return nil
}

func sing(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	c := socks.NewClient(N.SystemDialer, M.ParseSocksaddr(addr), socks.Version5, user, pass)
	return c.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(target))
}

// outline's ctx covers the TCP connect only.
func outlineSDK(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	c, err := outline.NewClient(&transport.TCPEndpoint{Address: addr})
	if err != nil {
		return nil, err
	}
	if user != "" {
		if err := c.SetCredentials([]byte(user), []byte(pass)); err != nil {
			return nil, err
		}
	}
	return c.DialStream(ctx, target)
}
