package server

import "syscall"

// noBroadcast clears SO_BROADCAST, which Go sets on UDP sockets (S5).
func noBroadcast(c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 0)
	}); err != nil {
		return err
	}
	return serr
}
