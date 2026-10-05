//go:build !plan9

package socks0

import (
	"errors"
	"slices"
	"syscall"
)

var (
	errMsgSize     error = syscall.EMSGSIZE
	errDestAddrReq error = syscall.EDESTADDRREQ
)

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
