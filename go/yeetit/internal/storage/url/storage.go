package url

import (
	"context"
	_ "embed"

	"github.com/go-faster/errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Storage struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Storage {
	return &Storage{
		pool: pool,
	}
}

var (
	//go:embed insert_url.sql
	sqlInsertURL string
	//go:embed get_url.sql
	sqlGetURL string
)

func (s *Storage) InsertURL(ctx context.Context, longURL, shortURL string) error {
	const op = "url.Storage.InsertURL"

	_, err := s.pool.Exec(ctx, sqlInsertURL, longURL, shortURL)
	if err != nil {
		return errors.Wrap(err, op)
	}

	return nil
}

var errShortURLNotFound = errors.New("short URL not found")

func (s *Storage) GetURL(ctx context.Context, shortURL string) (string, error) {
	const op = "url.Storage.GetURL"

	var longURL string
	err := s.pool.QueryRow(ctx, sqlGetURL, shortURL).Scan(&longURL)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", errors.Wrap(errShortURLNotFound, op)
		}

		return "", errors.Wrap(err, op)
	}

	return longURL, nil
}
