#!/usr/bin/env bash
# End-to-end test of a candidate CL/beacon endpoint against bera-proofs.
#
# Tier 1: probe the raw CL paths (scripts/probe_cl_endpoint.py).
# Tier 2: point bera-proofs at the endpoint, start the REST API, and generate a
#         real proof for `head` — exercising the full production path
#         (live beacon-state fetch -> SSZ deserialize -> Merkle proof). This is
#         what catches Beacon-Kit response-shape mismatches that a raw probe can't.
#
# Usage:
#   export CL_RPC_URL='https://host/<token>'          # kept out of shell history
#   scripts/test_cl_endpoint_e2e.sh [validator_index] # default validator index 0
#
# Endpoint is read from CL_RPC_URL | BEACON_RPC_URL_MAINNET | BEACON_RPC_URL.
# The token is never printed (server logs are redacted before display).
# Exit 0 iff Tier 1 passes AND /health reports beacon_api=true AND a proof is built.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
VALIDATOR="${1:-0}"
PORT="${PORT:-8099}"
ENDPOINT="${CL_RPC_URL:-${BEACON_RPC_URL_MAINNET:-${BEACON_RPC_URL:-}}}"
[ -n "$ENDPOINT" ] || { echo "ERROR: set CL_RPC_URL (or BEACON_RPC_URL_MAINNET)" >&2; exit 2; }

# redact any URL path/token in piped text -> scheme://host/<redacted>
redact() { sed -E 's#(https?://[^/[:space:]"]+)/[^[:space:]"]*#\1/<redacted>#g'; }

echo "### Tier 1 — raw CL probe"
CL_RPC_URL="$ENDPOINT" python3 "$HERE/probe_cl_endpoint.py" --timeout 60 \
  || { echo "Tier 1 failed — skipping the end-to-end run."; exit 1; }

echo; echo "### Tier 2 — end-to-end proof via bera-proofs API"
LOG="$(mktemp)"; HEALTH="$(mktemp)"; PROOF="$(mktemp)"
cleanup() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -f "$LOG" "$HEALTH" "$PROOF"; }
trap cleanup EXIT

export BEACON_NETWORK=mainnet BEACON_RPC_URL_MAINNET="$ENDPOINT"
( cd "$REPO" && poetry run uvicorn bera_proofs.api.rest_api:app --host 127.0.0.1 --port "$PORT" ) >"$LOG" 2>&1 &
SRV=$!

ready=""
for _ in $(seq 1 30); do
  sleep 1
  if curl -fsS "http://127.0.0.1:$PORT/health" -o "$HEALTH" 2>/dev/null; then ready=1; break; fi
  if ! kill -0 "$SRV" 2>/dev/null; then
    echo "FAIL: API server exited during startup (poetry deps installed? \`poetry install\`). Last log:"
    tail -15 "$LOG" | redact; exit 1
  fi
done
[ -n "$ready" ] || { echo "FAIL: /health not ready within 30s"; tail -15 "$LOG" | redact; exit 1; }

echo "health: $(cat "$HEALTH")"
grep -q '"beacon_api"[[:space:]]*:[[:space:]]*true' "$HEALTH" \
  || { echo "FAIL: /health beacon_api != true"; exit 1; }

echo "proof : GET /proofs/combined/$VALIDATOR?slot=head"
if curl -fsS "http://127.0.0.1:$PORT/proofs/combined/$VALIDATOR?slot=head" -o "$PROOF" 2>/dev/null \
   && grep -q 'validator_proof' "$PROOF"; then
  echo "PASS: proof generated ($(wc -c <"$PROOF") bytes, validator_proof present)"
  echo; echo "E2E VERDICT: PASS — bera-proofs builds a real proof against this endpoint."
  exit 0
fi
echo "FAIL: proof not generated. Response/log tail:"
{ head -c 400 "$PROOF" 2>/dev/null; echo; tail -15 "$LOG"; } | redact
echo; echo "E2E VERDICT: FAIL"
exit 1
