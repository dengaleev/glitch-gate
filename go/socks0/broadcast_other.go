//go:build !unix && !windows

package socks0

import "syscall"

func noBroadcast(syscall.RawConn) error { return nil }
