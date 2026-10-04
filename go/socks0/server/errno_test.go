//go:build !plan9

package server_test

import (
	"os"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var errRefused error = syscall.ECONNREFUSED

const repRefused = wire.ReplyConnectionRefused

func errnoReplies() []struct {
	err  error
	want wire.Reply
} {
	return []struct {
		err  error
		want wire.Reply
	}{
		{os.NewSyscallError("connect", syscall.ECONNREFUSED), 5},
		{syscall.ENETUNREACH, 3},
		{syscall.EHOSTUNREACH, 4},
		{syscall.ETIMEDOUT, 6},
		{syscall.EACCES, 2},
		{syscall.EPERM, 2},
		{syscall.EINVAL, 1},
	}
}
