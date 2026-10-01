# syntax=docker/dockerfile:1.7
FROM python:3.12-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels ".[gcp]"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8080 \
    PORTAL_ENV=prod PORTAL_STORAGE_BACKEND=gcs
RUN useradd --system --uid 10001 --home /app portal
WORKDIR /app
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels
COPY alembic.ini ./
COPY migrations ./migrations
RUN mkdir -p /app/var && chown portal /app/var
USER portal
EXPOSE 8080
# --proxy-headers fica DESLIGADO: o IP do cliente é extraído com
# PORTAL_TRUSTED_PROXY_HOPS (evita confiar em X-Forwarded-For forjado).
CMD ["sh", "-c", "exec uvicorn portal.web.asgi:app --host 0.0.0.0 --port ${PORT} --no-proxy-headers --no-server-header"]
