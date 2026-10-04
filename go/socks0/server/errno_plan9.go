package server

import "github.com/dengaleev/glitch-gate/go/socks0/wire"

func errnoReply(error) (wire.Reply, bool) { return 0, false }
