#!/usr/bin/env sh
set -e

HOST="${API_HOST:-0.0.0.0}"
PORT="${API_PORT:-8000}"
EXTRA="${API_EXTRA_ARGS:-}"

# If no args or first arg is 'serve', run the API server with env-configured host/port.
# Otherwise, run arbitrary CLI subcommands (e.g., "validator", "balance", ...).
if [ "$#" -eq 0 ] || [ "$1" = "serve" ]; then
  [ "$1" = "serve" ] && shift
  exec poetry run python -m bera_proofs.cli serve --host "$HOST" --port "$PORT" $EXTRA "$@"
else
  exec poetry run python -m bera_proofs.cli "$@"
fi
