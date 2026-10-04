//go:build !plan9

package socks0

import (
	"errors"
	"slices"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var (
	errMsgSize     error = syscall.EMSGSIZE
	errDestAddrReq error = syscall.EDESTADDRREQ
)

func (e *ReplyError) isErrno(target error) bool {
	switch e.Reply {
	case wire.ReplyNetworkUnreachable:
		return target == syscall.ENETUNREACH
	case wire.ReplyHostUnreachable:
		return target == syscall.EHOSTUNREACH
	case wire.ReplyConnectionRefused:
		return target == syscall.ECONNREFUSED
	case wire.ReplyTTLExpired:
		return target == syscall.ETIMEDOUT
	}
	return false
}

func errnoKind(err error) Kind {
	is := func(errnos ...syscall.Errno) bool {
		return slices.ContainsFunc(errnos, func(e syscall.Errno) bool { return errors.Is(err, e) })
	}
	switch {
	case is(syscall.ECONNREFUSED):
		return KindRefused
	case is(syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE):
		return KindReset
	case is(syscall.ENETUNREACH, syscall.EHOSTUNREACH):
		return KindUnreachable
	}
	return ""
}
