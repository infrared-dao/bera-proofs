#!/usr/bin/env bash

TAG=${1:-production-mainnet}
IMAGE=471112650735.dkr.ecr.eu-central-1.amazonaws.com/backend/bera-proofs
echo "pushing image... $IMAGE:$TAG"
echo ""

aws --profile default ecr get-login-password --region eu-central-1 |  docker login --username AWS --password-stdin $IMAGE

docker push ${IMAGE}:${TAG}
