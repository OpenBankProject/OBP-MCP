# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OBP-MCP is a Model Context Protocol (MCP) server for the Open Bank Project API, built with `fastmcp`. It exposes 600+ OBP API endpoints to AI assistants through a hybrid tag-based routing system with OAuth 2.1 authentication.

## Common Commands

All commands use `uv` as the package manager:

```bash
# Install/sync dependencies
uv sync

# Run the server
./run_server.sh              # normal mode
./run_server.sh --watch      # auto-reload on file changes
uv run python src/mcp_server_obp/server.py  # direct

# Run tests
uv run pytest                         # all tests
uv run pytest tests/test_auth.py      # single file
uv run pytest -v                      # verbose

# Generate data indexes (requires OBP_BASE_URL in .env)
uv run python scripts/generate_endpoint_index.py
uv run python scripts/generate_glossary_index.py

# Add a dependency
uv add <package>
```

## Architecture

### Three-Step Endpoint Discovery (not RAG)

The server avoids vector databases. Instead it uses a tag-based discovery pattern:

1. **`list_endpoints_by_tag(tags)`** — returns lightweight summaries (~50-100 tokens each) from `endpoint_index.json` (250KB)
2. **`get_endpoint_schema(endpoint_id)`** — lazy-loads full OpenAPI schema from `endpoint_schemas.json` (4.3MB)
3. **`call_obp_api(endpoint_id, ...)`** — executes the actual HTTP request against OBP-API

Additional tools: `list_glossary_terms(search_query)` and `get_glossary_term(term_id)` for 800+ banking terms.

### Key Modules

- **`src/mcp_server_obp/server.py`** — FastMCP server definition, all tool/resource registrations
- **`src/mcp_server_obp/auth.py`** — Multi-provider auth: `bearer-only`, `obp-oidc`, `keycloak`, `none`
- **`src/mcp_server_obp/lifespan.py`** — Server lifecycle, startup index updates, periodic refresh
- **`src/tools/endpoint_index.py`** — `EndpointIndex` class with strict Pydantic types, tag filtering, lazy schema loading
- **`src/tools/glossary_index.py`** — `GlossaryIndex` class for term search/retrieval
- **`database/`** — JSON index files, `startup_updater.py` for auto-refresh, `data_hash_manager.py` for change detection
- **`scripts/`** — Standalone generators that fetch from OBP resource-docs/swagger API

### Authentication Modes (`AUTH_PROVIDER` env var)

| Mode | Use Case | Notes |
|------|----------|-------|
| `bearer-only` | Internal agents (e.g., Opey) | JWT validation only, multi-issuer support |
| `obp-oidc` | External MCP clients | Full OAuth 2.1 + Dynamic Client Registration |
| `keycloak` | External MCP clients | OAuth 2.1 + minimal DCR proxy workaround |
| `none` | Development/testing | No auth required |

### Data Flow

- JSON indexes stored in `database/` — no external database needed
- `DataHashManager` compares hashes to detect upstream changes
- `IndexStartupUpdater` refreshes on startup if `UPDATE_INDEX_ON_STARTUP=true`
- Periodic refresh configurable via `REFRESH_INTERVAL_MINUTES`

## Configuration

All config via environment variables. Copy `.env.example` to `.env`. Key variables:

- `OBP_BASE_URL` — OBP API instance URL
- `OBP_API_VERSION` — API version (e.g., `v6.0.0`)
- `AUTH_PROVIDER` — Authentication mode (see table above)
- `OBP_AUTHORIZATION_VIA` — How API calls are authorized: `oauth`, `consent`, or `none`
- `LOG_LEVEL` — `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`
- `FASTMCP_HOST` / `FASTMCP_PORT` — Server bind address

## Testing Conventions

- Tests live in `tests/` using pytest
- `conftest.py` provides shared fixtures (auth URLs, JWT payloads, `clean_env` for env isolation)
- Test files: `test_auth.py` (auth providers), `test_endpoint_index.py` (endpoint index)
- Tests use `pytest-asyncio` for async code
