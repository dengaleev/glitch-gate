package socks0_test

import (
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

// The config error's Addr must not claim DST 0.0.0.0:0 as the target.
func TestV2UDPBadTargetErrorAddr(t *testing.T) {
	d := &socks0.Dialer{ProxyAddr: "192.0.2.1:1080", ProxyDial: noDial(t)}
	for _, tc := range [][2]string{{"udp", "nonsense"}, {"udp6", "192.0.2.1:53"}, {"udp", "host:99999"}} {
		_, err := d.DialContext(t.Context(), tc[0], tc[1])
		_, terr := d.DialContext(t.Context(), "tcp"+tc[0][3:], tc[1])
		t.Logf("udp: %v\n    tcp: %v", err, terr)
		if socks0.KindOf(err) != socks0.KindConfig {
			t.Errorf("%v: kind %q", tc, socks0.KindOf(err))
		}
		if s := err.Error(); len(s) > 0 && contains(s, "0.0.0.0:0") {
			t.Errorf("%v: error names DST 0.0.0.0:0 as the target: %v", tc, err)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
