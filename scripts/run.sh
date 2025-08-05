#!/bin/bash
# Exit immediately if a command exits with a non-zero status
set -euxo pipefail

image_tag=${1:-production-mainnet}

rm -rf /tmp/bera-proofs_*
logdir=$(mktemp -d -t bera-proofs_XXXXXX)
chmod 777 "${logdir}"
ls -ld "${logdir}"

# Retrieve API key from AWS Secrets Manager
furthermore_api_key=$(aws secretsmanager get-secret-value \
  --secret-id furthermore-api-key \
  --query SecretString --output text)

# Stop and remove any existing container
docker stop bera-proofs_service || true
docker rm bera-proofs_service || true

# Run the bera-proofs docker container in detached mode
container=$(docker run -d \
  --network host \
  -v ~/.aws:/root/.aws:ro \
  -v "${logdir}":/app/logs/:rw \
  -e BEACON_NETWORK=mainnet \
  -e BEACON_RPC_URL_MAINNET=https://mainnet.beacon-1.bera.de.lgns.net \
  -e API_HOST=0.0.0.0 \
  -e API_PORT=8000 \
  --name bera-proofs_service \
  471112650735.dkr.ecr.eu-central-1.amazonaws.com/backend/bera-proofs:"${image_tag}" \
  bera-proofs \
  --log_file=/app/logs/bera-proofs.log
)

echo "Started container: ${container}"

# Forward logs in the background
docker logs -f bera-proofs_service > "${logdir}/bera-proofs.log" 2>&1 &
logs_pid=$!
trap 'kill "${logs_pid}" 2>/dev/null || true' EXIT

# Wait until the container exits
docker wait bera-proofs_service

# Print final log output
tail "${logdir}/bera-proofs.log"
