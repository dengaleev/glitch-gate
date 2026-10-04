//go:build unix

package sockopt

import "syscall"

// NoBroadcast clears SO_BROADCAST, which Go sets on UDP sockets.
func NoBroadcast(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return serr
}
