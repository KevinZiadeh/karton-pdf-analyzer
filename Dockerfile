# Official UV base image with Python 3.12 - https://github.com/astral-sh/uv-docker-example/blob/main/compose.ym
FROM astral/uv:python3.12-bookworm-slim AS base

# Set working directory
WORKDIR /app

# Environment configuration
ENV UV_COMPILE_BYTECODE=1 \
    # Enable bytecode compilation
    UV_TOOL_BIN_DIR=/usr/local/bin \ 
    # Ensure installed tools can be executed out of the box
    UV_LINK_MODE=copy \
    # Copy from the cache instead of linking since it's a mounted volume
    PATH="/app/.venv/bin:$PATH"
    # Place executables in the environment at the front of the path

# Pre-install needed packages
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get clean && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/apt/lists/partial \
    && apt-get update -o Acquire::CompressionTypes::Order::=gz

# ---------- Build stage ----------
FROM base AS build

# Install the project's dependencies using the lockfile and settings
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock,readonly \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml,readonly \
    uv sync --locked --no-install-project --no-dev

# Then, add the rest of the project source code and install it
# Installing separately from its dependencies allows optimal layer caching
COPY . /app
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Apply required fix to Karton package
RUN sed -i \
    "s/{bind\.identity:50} {bind\.service_version or \"-\"/{bind.identity:50} {bind.service_version or '-'}/g" \
    /app/.venv/lib/python3.12/site-packages/karton/core/main.py

# ---------- Final runtime stage ----------
FROM base AS runtime

# Copy virtual environment and app from build stage
COPY --from=build /app /app

# Default entrypoint
ENTRYPOINT ["karton-pdf-analyzer"]
