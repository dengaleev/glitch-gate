package server_test

import (
	"errors"

	"github.com/dengaleev/glitch-gate/go/socks0/wire"
)

var errRefused = errors.New("connection refused")

const repRefused = wire.ReplyGeneralFailure

func errnoReplies() []struct {
	err  error
	want wire.Reply
} {
	return nil
}
