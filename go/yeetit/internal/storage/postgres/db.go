package postgres

import (
	"context"

	"github.com/go-faster/errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Database struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Database, error) {
	const op = "postgres.New"

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.Wrap(err, op)
	}

	return &Database{
		pool: pool,
	}, nil
}

func (db *Database) Pool() *pgxpool.Pool { return db.pool }
func (db *Database) Close()              { db.pool.Close() }
