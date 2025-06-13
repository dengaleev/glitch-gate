package main

import (
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/app"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/config"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/storage/url"
	"go.uber.org/fx"
)

func main() {
	fx.New(
		fx.Provide(config.Parse),

		fx.Provide(app.NewDatabase),
		fx.Provide(app.NewURLStorage),

		fx.Invoke(func(*url.Storage) error {
			return nil
		}),
	).Run()
}
