//go:build !plan9

// Package errno mirrors SOCKS5 REP codes 03–06 and their errnos, both ways.
package errno

import (
	"errors"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var replies = [...]struct {
	rep   wire.Reply
	errno syscall.Errno
}{
	{wire.ReplyNetworkUnreachable, syscall.ENETUNREACH},
	{wire.ReplyHostUnreachable, syscall.EHOSTUNREACH},
	{wire.ReplyConnectionRefused, syscall.ECONNREFUSED},
	{wire.ReplyTTLExpired, syscall.ETIMEDOUT},
}

// Is reports whether target is the errno rep mirrors.
func Is(rep wire.Reply, target error) bool {
	for _, r := range replies {
		if r.rep == rep {
			return target == r.errno
		}
	}
	return false
}

// Reply is the REP mirroring the first syscall.Errno in err's tree.
func Reply(err error) (wire.Reply, bool) {
	e, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return 0, false
	}
	for _, r := range replies {
		if r.errno == e {
			return r.rep, true
		}
	}
	return 0, false
}
