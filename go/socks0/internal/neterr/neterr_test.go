package neterr

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

type timeoutErr bool

func (e timeoutErr) Error() string { return fmt.Sprint("timeout ", bool(e)) }
func (e timeoutErr) Timeout() bool { return bool(e) }

func TestIsTimeout(t *testing.T) {
	errTest := errors.New("test")
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errTest, false},
		{timeoutErr(true), true},
		{timeoutErr(false), false},
		{fmt.Errorf("w: %w", timeoutErr(true)), true},
		{fmt.Errorf("w: %w", fmt.Errorf("%w %w", timeoutErr(false), timeoutErr(true))), true},
		{errors.Join(errTest, timeoutErr(false)), false},
	} {
		if got := IsTimeout(tc.err); got != tc.want {
			t.Errorf("IsTimeout(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestTruncated(t *testing.T) {
	errTest := errors.New("test")
	trunc := &wire.ProtocolError{Stage: wire.StageReply, Err: io.ErrUnexpectedEOF}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, wire.ErrIncomplete, fmt.Errorf("w: %w", io.EOF)} {
		if got := Truncated(wire.StageReply, err); !reflect.DeepEqual(got, trunc) {
			t.Errorf("Truncated(%v) = %#v", err, got)
		}
	}
	if got := Truncated(wire.StageReply, errTest); got != errTest {
		t.Errorf("Truncated(errTest) = %v", got)
	}
	if got := Truncated(wire.StageReply, nil); got != nil {
		t.Errorf("Truncated(nil) = %v", got)
	}
}
