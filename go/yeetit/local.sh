#!/bin/bash

export POSTGRES_DSN="postgres://postgres:password@localhost:5432/postgres"
export DOMAIN=""

exec go run ./cmd
