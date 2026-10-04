//go:build !unix && !windows

package server

import "syscall"

func noBroadcast(syscall.RawConn) error { return nil }
