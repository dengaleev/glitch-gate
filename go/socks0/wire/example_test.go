package wire_test

import (
	"errors"
	"fmt"
	"log"
	"net"
	"slices"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

func ExampleAppendRequest() {
	target, err := wire.ParseAddr("example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	// A pipelined handshake: greeting, auth and request in one buffer.
	b, err := wire.AppendGreeting(nil, wire.MethodUserPass)
	if err != nil {
		log.Fatal(err)
	}
	if b, err = wire.AppendUserPass(b, "user", "pass"); err != nil {
		log.Fatal(err)
	}
	if b, err = wire.AppendRequest(b, wire.CmdConnect, target); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("% x\n", b)
	// Output:
	// 05 01 02 01 04 75 73 65 72 04 70 61 73 73 05 01 00 03 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 01 bb
}

func ExampleParseReply() {
	// Bytes as they arrive, e.g. in an event loop.
	buf := []byte{0x05, 0x00, 0x00, 0x01, 192, 0, 2, 1}
	_, _, need, err := wire.ParseReply(buf, wire.CmdConnect)
	if errors.Is(err, wire.ErrIncomplete) {
		fmt.Println("wait until", need, "bytes")
	}
	buf = append(buf, 0x04, 0x38)
	rep, bound, n, err := wire.ParseReply(buf, wire.CmdConnect)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(rep, bound, n)
	// Output:
	// wait until 10 bytes
	// succeeded 192.0.2.1:1080 10
}

// A no-auth CONNECT server handshake.
func ExampleReadRequest() {
	c, client := net.Pipe() // c is accepted from a listener
	done := make(chan struct{})
	go runClient(client, done)

	methods, err := wire.ReadGreeting(c)
	if err != nil {
		log.Fatal(err)
	}
	if !slices.Contains(methods, wire.MethodNoAuth) {
		c.Write(wire.AppendMethodSelection(nil, wire.MethodNoAcceptable))
		return
	}
	c.Write(wire.AppendMethodSelection(nil, wire.MethodNoAuth))
	cmd, target, err := wire.ReadRequest(c)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(cmd, target)
	bound, _ := wire.ParseAddr("0.0.0.0:0")
	reply, _ := wire.AppendReply(nil, wire.ReplySucceeded, bound)
	c.Write(reply)
	<-done
	// Output:
	// CONNECT example.com:443
	// client: succeeded 0.0.0.0:0
}

// runClient is the client side of ExampleReadRequest.
func runClient(c net.Conn, done chan<- struct{}) {
	defer close(done)
	greeting, _ := wire.AppendGreeting(nil, wire.MethodNoAuth)
	c.Write(greeting)
	if _, err := wire.ReadMethodSelection(c); err != nil {
		log.Fatal(err)
	}
	target, _ := wire.ParseAddr("example.com:443")
	req, _ := wire.AppendRequest(nil, wire.CmdConnect, target)
	c.Write(req)
	rep, bound, err := wire.ReadReply(c, wire.CmdConnect)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("client:", rep, bound)
}
