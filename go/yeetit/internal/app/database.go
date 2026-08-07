package app

import (
	"context"

	"github.com/dengaleev/glitch-gate/go/yeetit/internal/config"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/storage/postgres"
	"github.com/dengaleev/glitch-gate/go/yeetit/internal/storage/url"
	"go.uber.org/fx"
)

func NewDatabase(lc fx.Lifecycle, cfg *config.Config) (*postgres.Database, error) {
	db, err := postgres.New(context.Background(), cfg.PostgresDSN)
	if err != nil {
		return nil, err
	}

	lc.Append(fx.StopHook(db.Close))

	return db, nil
}

func NewURLStorage(db *postgres.Database) *url.Storage {
	return url.New(db.Pool())
}
