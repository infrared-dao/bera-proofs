#!/usr/bin/env bash
set -euo pipefail

TAG="${1:-production-mainnet}"            # default tag if none supplied
IMAGE_NAME="backend/bera-proofs"
REGISTRY="471112650735.dkr.ecr.eu-central-1.amazonaws.com"

echo "🔨  Building $REGISTRY/$IMAGE_NAME:$TAG"

DOCKER_BUILDKIT=1 docker build \
  --platform linux/amd64 \
  --build-arg BUILD_VERSION="$(git rev-parse --short=12 HEAD)" \
  -f scripts/Dockerfile \
  -t "$IMAGE_NAME:$TAG" \
  .

docker tag "$IMAGE_NAME:$TAG" "$REGISTRY/$IMAGE_NAME:$TAG"
echo "✅  Image tagged as $REGISTRY/$IMAGE_NAME:$TAG"
