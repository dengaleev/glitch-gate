package main

import (
	"net/http"

	"github.com/dengaleev/glitch-gate/go/yeetit/internal/app"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/config"
	"go.uber.org/fx"
)

func main() {
	fx.New(
		fx.Provide(config.Parse),

		fx.Provide(app.NewDatabase),
		fx.Provide(app.NewURLStorage),

		fx.Provide(app.NewServer),

		fx.Invoke(func(*http.Server) error { return nil }),
	).Run()
}
