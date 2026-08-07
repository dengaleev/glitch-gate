package schema

import "embed"

//go:embed db/migrations/*.sql
var PostgresMigrations embed.FS
