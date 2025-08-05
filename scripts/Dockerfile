# ── syntax directive gives us --mount=type=cache ───────────────────────────────
# (If you don’t use BuildKit everywhere, you can delete the first line.)
# syntax=docker/dockerfile:1.7

# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.12.3-slim AS base

# ------------------------------------------------------------------------------
# 1. System packages (gcc only, not full build-essential → smaller download)
# ------------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc git curl && \
    rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# 2. Poetry installation
# ------------------------------------------------------------------------------
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VERSION="1.8.2" \
    POETRY_VIRTUALENVS_CREATE="false" \
    POETRY_NO_INTERACTION="1"
ENV PATH="${POETRY_HOME}/bin:${PATH}"

RUN curl -sSL https://install.python-poetry.org | python3 -

# ------------------------------------------------------------------------------
# 3. Install *dependencies only* (good cache behaviour)
#    Copy just the lockfile first so Docker reuses the layer
# ------------------------------------------------------------------------------
WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN poetry install --no-ansi --no-interaction --no-root \
    --only=main      # install default dependencies, skip extras/tests

# ------------------------------------------------------------------------------
# 4. Copy project source code and install it (fast, local only)
# ------------------------------------------------------------------------------
COPY src ./src

# Install console-script entry points *without* hitting the network again
RUN poetry install --no-ansi --no-interaction --only-root

# ------------------------------------------------------------------------------
# 5. OCI labels & metadata (optional but useful)
# ------------------------------------------------------------------------------
ARG BUILD_VERSION=local
LABEL org.opencontainers.image.source="https://github.com/infrared-dao/bera-proofs" \
      org.opencontainers.image.revision="$BUILD_VERSION" \
      org.opencontainers.image.title="bera-proofs" \
      org.opencontainers.image.description="Berachain Merkle Proof Generator " \
      org.opencontainers.image.created="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"

# -------------------------------------------------------------------
# 6. Entrypoint – choose which collector at `docker run`
# -------------------------------------------------------------------

# default network (can be overridden with `-e BEACON_NETWORK=…`)
ENV BEACON_NETWORK=mainnet

# run "poetry run python -m bera_proofs.cli <args…>"
ENTRYPOINT ["poetry", "run", "python", "-m", "bera_proofs.cli"]

# if you do `docker run image` this will become:
#   poetry run python -m bera_proofs.cli serve
CMD ["serve"]
