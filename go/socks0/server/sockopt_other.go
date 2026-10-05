//go:build !linux

package server

import (
	"net"
	"time"
)

func setUserTimeout(net.Conn, time.Duration) {}
