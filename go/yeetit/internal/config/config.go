package config

import (
	"github.com/go-faster/errors"
	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Address string `env:"ADDRESS" env-default:":8000"`

	Domain string `env:"DOMAIN" env-required:"true"`

	PostgresDSN string `env:"POSTGRES_DSN" env-required:"true"`
}

func Parse() (*Config, error) {
	const op = "config.Parse"

	var cfg Config
	if err := cleanenv.ReadEnv(cfg); err != nil {
		return nil, errors.Wrap(err, op)
	}

	return &cfg, nil
}
