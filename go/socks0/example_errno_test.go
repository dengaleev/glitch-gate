//go:build !plan9

package socks0_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"

	"github.com/dengaleev/glitch-gate/go/socks0"
)

func ExampleReplyError() {
	d := &socks0.Dialer{ProxyAddr: "127.0.0.1:1080"}
	_, err := d.DialContext(context.Background(), "tcp", "10.255.255.1:80")
	if errors.Is(err, syscall.ECONNREFUSED) {
		fmt.Println("refused by the target, as seen by the proxy")
	}
	if re, ok := errors.AsType[*socks0.ReplyError](err); ok {
		fmt.Println("proxy replied:", re.Reply)
	}
	if pe, ok := errors.AsType[*socks0.ProtocolError](err); ok && pe.Hint != "" {
		fmt.Println("not a SOCKS5 proxy?", pe.Hint)
	}
}

// A proxy that is down: refused at the proxy dial, before any SOCKS byte.
func ExampleKindOf() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln.Close() // nothing listens there now
	d := &socks0.Dialer{ProxyAddr: ln.Addr().String()}
	_, err = d.DialContext(context.Background(), "tcp", "example.com:80")
	he, _ := errors.AsType[*socks0.HandshakeError](err)
	fmt.Println(socks0.KindOf(err), he.Stage)
	// Output: refused proxy dial
}
