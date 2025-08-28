# syntax=docker/dockerfile:1.7

FROM python:3.12.3-slim AS base

# 1) System packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc git curl && \
    rm -rf /var/lib/apt/lists/*

# 2) Poetry
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VERSION="1.8.2" \
    POETRY_VIRTUALENVS_CREATE="false" \
    POETRY_NO_INTERACTION="1"
ENV PATH="${POETRY_HOME}/bin:${PATH}"
RUN curl -sSL https://install.python-poetry.org | python3 -

# 3) Deps-only layer
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-ansi --no-interaction --no-root --only=main

# 4) App code + project install
COPY src ./
RUN poetry install --no-ansi --no-interaction --only-root

# 5) Metadata
ARG BUILD_VERSION=local
LABEL org.opencontainers.image.source="https://github.com/infrared-dao/bera-proofs" \
      org.opencontainers.image.revision="$BUILD_VERSION" \
      org.opencontainers.image.title="bera-proofs" \
      org.opencontainers.image.description="Berachain Merkle Proof Generator " \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# 6) Runtime config
ENV BEACON_NETWORK=mainnet
# Defaults that you can override at `docker run`
ENV API_HOST=0.0.0.0
ENV API_PORT=8000
# Optional: pass extra flags to `serve`, e.g. `--dev`
ENV API_EXTRA_ARGS=

# Expose the default port
EXPOSE 8000

# Entry wrapper: maps env -> serve args, but still allows other subcommands
COPY scripts/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
