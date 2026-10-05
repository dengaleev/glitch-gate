package socks0_test

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// Where TFO is not supported, FastOpenDial opens no socket and fails as a config error: nothing is sent.
func TestFastOpenUnsupported(t *testing.T) {
	if socks0.FastOpenSupported {
		t.Skip("supported here")
	}
	var controlled bool
	dial := socks0.FastOpenDial(&net.Dialer{Control: func(string, string, syscall.RawConn) error {
		controlled = true
		return nil
	}})
	c, err := dial(t.Context(), "tcp", "127.0.0.1:1")
	if c != nil || !errors.Is(err, errors.ErrUnsupported) || controlled {
		t.Errorf("dial = %v, %v; socket opened: %v", c, err, controlled)
	}
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1", ProxyDial: socks0.FastOpenDial(nil)}
	_, err = d.DialContext(t.Context(), "tcp", "example.com:80")
	if he := handshakeErrOf(t, err); !errors.Is(err, errors.ErrUnsupported) || socks0.KindOf(err) != socks0.KindConfig || he.Stage != socks0.StageProxyDial {
		t.Errorf("DialContext: %v (kind %q, stage %q)", err, socks0.KindOf(err), he.Stage)
	}
}
