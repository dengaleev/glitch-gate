package app

import (
	"net"
	"net/http"

	"github.com/dengaleev/glitch-gate/go/yeetit/internal/config"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/http/handler/ping"
	"go.uber.org/fx"
)

func NewServer(
	lc fx.Lifecycle,
	cfg *config.Config,
	router *http.ServeMux,
) (*http.Server, error) {
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{
		Handler: router,
	}

	lc.Append(fx.StartStopHook(
		func() error { return srv.Serve(listener) },
		srv.Shutdown,
	))

	return srv, nil
}

func NewRouter() *http.ServeMux {
	mux := http.NewServeMux()

	mux.Handle("GET /ping", ping.New())
	// mux.Handle("POST /api/v1/shorten", shorten.New())

	return mux
}
