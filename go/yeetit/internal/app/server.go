package app

import (
	"net"
	"net/http"

	"github.com/dengaleev/glitch-gate/go/yeetit/internal/config"
	"go.uber.org/fx"
)

func NewServer(
	lc fx.Lifecycle,
	cfg *config.Config,
) (*http.Server, error) {
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{}

	lc.Append(fx.StartStopHook(
		func() error { return srv.Serve(listener) },
		srv.Shutdown,
	))

	return srv, nil
}
