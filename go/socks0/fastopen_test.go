package socks0_test

import (
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

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
	if _, err := d.DialContext(t.Context(), "tcp", "example.com:80"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("DialContext: %v", err)
	}
}
