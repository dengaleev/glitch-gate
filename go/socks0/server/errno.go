//go:build !plan9

package server

import (
	"errors"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func errnoReply(err error) (wire.Reply, bool) {
	errno, ok := errors.AsType[syscall.Errno](err)
	if !ok {
		return 0, false
	}
	switch errno {
	case syscall.EACCES, syscall.EPERM:
		return wire.ReplyNotAllowed, true
	case syscall.ENETUNREACH:
		return wire.ReplyNetworkUnreachable, true
	case syscall.EHOSTUNREACH:
		return wire.ReplyHostUnreachable, true
	case syscall.ECONNREFUSED:
		return wire.ReplyConnectionRefused, true
	case syscall.ETIMEDOUT:
		return wire.ReplyTTLExpired, true
	}
	return 0, false
}
