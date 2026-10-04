//go:build unix

package socks0

import "syscall"

// noBroadcast clears SO_BROADCAST against a hostile BND directed broadcast.
func noBroadcast(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return serr
}
