
FROM python:3.12-slim AS builder
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY src/ ./src/
COPY database/ ./database/
COPY scripts/ ./scripts/
COPY pyproject.toml uv.lock ./
COPY run_server.sh ./
RUN chmod +x run_server.sh
RUN mkdir -p database/data

ENV PYTHONUNBUFFERED=1
ENV PATH="/app/.venv/bin:$PATH"
ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=9100
ENV OBP_BASE_URL=https://apisandbox.openbankproject.com
ENV OBP_API_VERSION=v5.1.0

EXPOSE 9100

CMD ["sh", "-c", "uv run python scripts/generate_endpoint_index.py && uv run python scripts/generate_glossary_index.py && ./run_server.sh"]
