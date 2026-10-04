//go:build !plan9

package errno

import (
	"errors"
	"fmt"
	"syscall"
	"testing"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func TestReplies(t *testing.T) {
	for _, r := range replies {
		if !Is(r.rep, r.errno) {
			t.Errorf("Is(%v, %v) = false", r.rep, r.errno)
		}
		if Is(r.rep, syscall.EPERM) {
			t.Errorf("Is(%v, EPERM) = true", r.rep)
		}
		if got, ok := Reply(fmt.Errorf("w: %w", r.errno)); !ok || got != r.rep {
			t.Errorf("Reply(%v) = %v, %v", r.errno, got, ok)
		}
	}
	if Is(wire.ReplyGeneralFailure, syscall.ECONNREFUSED) {
		t.Error("Is(GeneralFailure, ECONNREFUSED) = true")
	}
	for _, err := range []error{nil, errors.New("x"), syscall.EPERM, errors.Join(syscall.EPERM, syscall.ECONNREFUSED)} {
		if got, ok := Reply(err); ok {
			t.Errorf("Reply(%v) = %v", err, got)
		}
	}
}
