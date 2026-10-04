package wire

import (
	"errors"
	"strings"
	"testing"
)

func TestEncode(t *testing.T) {
	for _, v := range valid() {
		if v.nonCanonical {
			continue
		}
		dst := []byte{0xEE}
		got, err := v.c.encode(dst, v.want)
		if want := msg(0xEE, v.b); err != nil || string(got) != string(want) {
			t.Errorf("%s/%s: encode = % x, %v; want % x", v.c.stage, v.name, got, err, want)
		}
	}
}

func TestEncodeInvalid(t *testing.T) {
	long := strings.Repeat("x", 256)
	for name, f := range map[string]func([]byte) ([]byte, error){
		"greeting none": func(b []byte) ([]byte, error) { return AppendGreeting(b) },
		"greeting 256":  func(b []byte) ([]byte, error) { return AppendGreeting(b, make([]Method, 256)...) },
		"user 256":      func(b []byte) ([]byte, error) { return AppendUserPass(b, long, "") },
		"pass 256":      func(b []byte) ([]byte, error) { return AppendUserPass(b, "", long) },
		"request zero":  func(b []byte) ([]byte, error) { return AppendRequest(b, CmdConnect, Addr{}) },
		"reply zero":    func(b []byte) ([]byte, error) { return AppendReply(b, ReplySucceeded, Addr{}) },
		"udp zero":      func(b []byte) ([]byte, error) { return AppendUDPHeader(b, 0, Addr{}) },
		"binary zero":   Addr{}.AppendBinary,
		"request4 zero": func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdConnect, Addr{}, "") },
		"request4 IPv6": func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdConnect, v6, "") },
		"request4 0.0.0.0/24": func(b []byte) ([]byte, error) {
			return AppendRequest4(b, CmdConnect, mustAddr("0.0.0.7:80"), "")
		},
		"request4 0.0.0.0":    func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdBind, mustAddr("0.0.0.0:0"), "") },
		"request4 USERID 256": func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdConnect, v4, long) },
		"request4 USERID NUL": func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdConnect, v4, "a\x00b") },
		"request4 name NUL":   func(b []byte) ([]byte, error) { return AppendRequest4(b, CmdConnect, mustAddr("a\x00b:80"), "") },
		"reply4 IPv6":         func(b []byte) ([]byte, error) { return AppendReply4(b, Reply4Granted, v6) },
		"reply4 name":         func(b []byte) ([]byte, error) { return AppendReply4(b, Reply4Granted, dom) },
	} {
		for _, dst := range [][]byte{nil, {1, 2}, make([]byte, 1, 600)} {
			got, err := f(dst)
			if !errors.Is(err, ErrInvalid) || !same(got, dst) {
				t.Errorf("%s: got % x, %v; want dst unchanged, ErrInvalid", name, got, err)
			}
			if strings.Contains(err.Error(), long) {
				t.Errorf("%s: error %q holds the field", name, err)
			}
		}
	}
}

func TestUDPHeaderLen(t *testing.T) {
	for _, tt := range []struct {
		a    Addr
		want int
	}{
		{v4, 10},
		{v6, 22},
		{dom, 7 + len("example.com")},
		{mustAddr(long + ":1"), MaxUDPHeaderLen},
		{Addr{}, 0},
	} {
		if got := UDPHeaderLen(tt.a); got != tt.want {
			t.Errorf("UDPHeaderLen(%v) = %d, want %d", tt.a, got, tt.want)
		}
	}
	if MaxUDPHeaderLen != 262 {
		t.Errorf("MaxUDPHeaderLen = %d, want 262", MaxUDPHeaderLen)
	}
}

func TestAppendReply4Zero(t *testing.T) {
	if b, err := AppendReply4(nil, Reply4Rejected, Addr{}); err != nil || string(b) != string(msg(0, 0x5B, 0, 0, 0, 0, 0, 0)) {
		t.Errorf("AppendReply4(zero) = % x, %v", b, err)
	}
}
