//go:build !plan9

package server

import (
	"errors"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/internal/errno"
	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func errnoReply(err error) (wire.Reply, bool) {
	if e, ok := errors.AsType[syscall.Errno](err); ok && (e == syscall.EACCES || e == syscall.EPERM) {
		return wire.ReplyNotAllowed, true
	}
	return errno.Reply(err)
}
