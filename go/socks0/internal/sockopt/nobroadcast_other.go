//go:build !unix && !windows

package sockopt

import "syscall"

func NoBroadcast(syscall.RawConn) error { return nil }
