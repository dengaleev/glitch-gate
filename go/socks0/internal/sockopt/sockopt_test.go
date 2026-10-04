package sockopt

import (
	"errors"
	"syscall"
	"testing"
)

type failRawConn struct{ syscall.RawConn }

var errControl = errors.New("control")

func (failRawConn) Control(func(uintptr)) error { return errControl }

func TestNoBroadcastControlError(t *testing.T) {
	if err := NoBroadcast(failRawConn{}); err != errControl && err != nil {
		t.Fatalf("NoBroadcast = %v", err)
	}
}
