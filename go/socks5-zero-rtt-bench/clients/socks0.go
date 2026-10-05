package clients

import (
	"context"
	"net"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// socks0Dial returns a Client.Dial for socks0 in mode m. A Dialer per dial,
// as every other adapter builds its client per dial.
func socks0Dial(m socks0.Mode) func(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
	return func(ctx context.Context, addr, user, pass, target string) (net.Conn, error) {
		cfg := &socks0.Config{Mode: m}
		if user != "" {
			cfg.Auth = socks0.UserPass{Username: user, Password: pass}
		}
		d := &socks0.Dialer{ProxyAddr: addr, Config: cfg}
		return d.DialContext(ctx, "tcp", target)
	}
}
