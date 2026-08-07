package url_test

import (
	"context"
	"embed"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/dengaleev/glitch-gate/go/yeetit/internal/storage/url"
	"github.com/dengaleev/glitch-gate/go/yeetit/schema"
	"github.com/go-faster/errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

const postgresImage = "postgres:17-alpine"

type storageSuite struct {
	suite.Suite

	pool    *pgxpool.Pool
	storage *url.Storage
}

func (s *storageSuite) TestInsert() {
	t := s.T()

	longURL := "https://example.com/some/long/url"
	shortURL := "short123"

	require.NoError(t, s.storage.InsertURL(t.Context(), longURL, shortURL))

	retrievedURL, err := s.storage.GetURL(t.Context(), shortURL)
	require.NoError(s.T(), err)
	require.Equal(s.T(), longURL, retrievedURL)
}

func TestStorageSuite(t *testing.T) {
	container, err := postgres.Run(t.Context(), postgresImage,
		WithMigrations(schema.PostgresMigrations),
		postgres.BasicWaitStrategies())
	require.NoError(t, err, "failed to start postgres container")
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("failed to terminate postgres container: %v", err)
		}
	})

	pool, err := pgxpool.New(context.Background(), container.MustConnectionString(t.Context()))
	require.NoError(t, err, "failed to create connection pool")
	defer pool.Close()

	require.NoError(t, pool.Ping(t.Context()))

	suite.Run(t, &storageSuite{
		pool:    pool,
		storage: url.New(pool),
	})
}

func WithMigrations(initFs embed.FS) testcontainers.CustomizeRequestOption {
	const (
		op      = "WithMigrations"
		initDir = "/docker-entrypoint-initdb.d/"
	)

	return func(request *testcontainers.GenericContainerRequest) error {
		err := fs.WalkDir(initFs, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			file, err := initFs.Open(path)
			if err != nil {
				return err //nolint:wrapcheck
			}

			request.Files = append(request.Files, testcontainers.ContainerFile{ //nolint:exhaustruct
				Reader:            file,
				ContainerFilePath: filepath.Join(initDir, filepath.Base(path)),
				FileMode:          0o444, //nolint:mnd
			})

			return nil
		})
		if err != nil {
			return errors.Wrap(err, op)
		}

		return nil
	}
}
