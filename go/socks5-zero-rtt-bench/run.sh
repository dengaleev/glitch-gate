#!/usr/bin/env bash
# Builds the netem image and runs the benchmark in it.
# Args: `bench rtt` flags (e.g. -n 30 -rtts 0,20,80,200), or `check`.
# Env: PT_RTT (proxy↔target ms, default 20), SERVER (proxy impl; comma-separated:
# one clients table each, e.g. SERVER=armon/go-socks5,socks0/server).
set -euo pipefail
cd "$(dirname "$0")"

if ! docker info >/dev/null 2>&1; then
	echo "run.sh: docker is not running (on macOS: colima start)" >&2
	exit 1
fi

img=socks5-zero-rtt-bench
# Context: go/, so the build sees ../socks0 (go.mod replace).
docker build -q -f netem/Dockerfile -t "$img" .. >/dev/null

tty=
[[ -t 1 ]] && tty=-t # live progress line
# shellcheck disable=SC2086
exec docker run --rm --privileged $tty \
	-e PT_RTT="${PT_RTT:-20}" -e SERVER="${SERVER:-}" "$img" "$@"
