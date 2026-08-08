# syntax=docker/dockerfile:1.7
# ── Builder ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.8.17 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /build

# Dependency layer first so code edits don't invalidate the resolved wheels.
COPY pyproject.toml README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /opt/venv && \
    VIRTUAL_ENV=/opt/venv uv pip install -r pyproject.toml

COPY app ./app
RUN --mount=type=cache,target=/root/.cache/uv \
    VIRTUAL_ENV=/opt/venv uv pip install --no-deps .

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# curl is used by the container healthcheck; libpq for psycopg's binary build.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl libpq5 tini && \
    rm -rf /var/lib/apt/lists/*

# Run unprivileged: an agent that calls out to the internet should not be root.
RUN groupadd --system --gid 1001 app && \
    useradd --system --uid 1001 --gid app --create-home --shell /usr/sbin/nologin app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

COPY --from=builder --chown=app:app /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=app:app app ./app

USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${PORT}/health" || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers ${WEB_CONCURRENCY:-2} --proxy-headers --forwarded-allow-ips='*'"]
