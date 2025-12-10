# OBP-MCP
An MCP Server for the Open Bank Project (OBP) API

## Overview

OBP-MCP provides a Model Context Protocol (MCP) server that enables AI assistants to interact with the Open Bank Project API. It features a hybrid tag-based endpoint routing system designed for efficiency and cost-effectiveness when working with 600+ API endpoints.

## Features

- **🚀 Hybrid Tag-Based Routing**: Fast, cost-effective endpoint discovery
- **📊 Lightweight Index**: Minimal token usage with on-demand schema loading
- **🔧 Three Core Tools**:
  - `list_endpoints_by_tag` - Discover endpoints by category
  - `get_endpoint_schema` - Fetch full OpenAPI schemas on-demand
  - `call_obp_api` - Execute API requests with validation
- **📚 Backward Compatible**: Legacy RAG-based tools remain available

## Quick Start

### Prerequisites

- Python 3.12+
- OBP API access (base URL and API version)

### Setup

Install [uv](https://docs.astral.sh/uv/) on your machine:

#### MacOS/Linux
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

#### Windows
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

### Configuration

Create a `.env` file with your OBP API configuration:

```bash
OBP_BASE_URL=https://apisandbox.openbankproject.com
OBP_API_VERSION=v5.1.0
```

### Generate Endpoint Index

Generate the lightweight endpoint index from the OBP API:

```bash
python scripts/generate_endpoint_index.py
```

This creates `database/endpoint_index.json` with endpoint summaries.

## Usage

### Tool 1: List Endpoints by Tag

Discover endpoints filtered by tags:

```python
list_endpoints_by_tag(["Account", "Transaction"])
```

Returns lightweight summaries (id, method, path, summary, tags) without full schemas.

### Tool 2: Get Endpoint Schema

Fetch the full OpenAPI schema for a specific endpoint:

```python
get_endpoint_schema("vVERSION-getBanks")
```

### Tool 3: Call OBP API

Execute an API request:

```python
call_obp_api(
    "vVERSION-privateAccountsAtOneBank",
    path_params={"BANK_ID": "gh.29.uk"},
    headers={"Authorization": "DirectLogin token=..."}
)
```

## Documentation

- **[Hybrid Routing Guide](docs/HYBRID_ROUTING.md)** - Detailed architecture and usage
- **[Database README](database/README.md)** - Vector database setup (for RAG tools)

## Architecture

The new hybrid approach replaces expensive RAG operations with a three-step process:

1. **Tag Classification** - Identify relevant endpoint categories
2. **Lightweight Index** - Return endpoint summaries (minimal tokens)
3. **On-Demand Schema** - Load full schemas only when needed

See [docs/HYBRID_ROUTING.md](docs/HYBRID_ROUTING.md) for complete details.

## Migration from RAG

If you're using the deprecated `retrieve_endpoints()` tool:

**Old (RAG):**
```python
retrieve_endpoints("I need to get bank accounts")
```

**New (Hybrid):**
```python
# Step 1: Discover
list_endpoints_by_tag(["Account", "Bank"])

# Step 2: Get schema (if needed)
get_endpoint_schema("vVERSION-privateAccountsAtOneBank")

# Step 3: Call API
call_obp_api("vVERSION-privateAccountsAtOneBank", ...)
```

## Development

### Project Structure

```
OBP-MCP/
├── src/
│   ├── mcp_server_obp/     # MCP server implementation
│   │   └── server.py        # Tool definitions
│   ├── tools/
│   │   ├── endpoint_index.py # Hybrid routing implementation
│   │   └── retrieval/       # Legacy RAG tools
│   └── utils/               # Formatters and utilities
├── database/
│   ├── endpoint_index.json  # Lightweight endpoint index
│   └── populate_vector_db.py # RAG database loader
├── scripts/
│   └── generate_endpoint_index.py # Index generator
└── docs/
    └── HYBRID_ROUTING.md    # Architecture documentation
```

### Regenerating the Index

Update the endpoint index when the OBP API changes:

```bash
# Static endpoints (default)
python scripts/generate_endpoint_index.py

# Dynamic endpoints
python scripts/generate_endpoint_index.py --endpoints dynamic

# All endpoints
python scripts/generate_endpoint_index.py --endpoints all
```

## Contributing

Contributions are welcome! Please ensure:

1. Code follows existing patterns
2. Tools are well-documented
3. Changes maintain backward compatibility
4. Index generation works correctly

## License

[Add license information]

## Support

For issues or questions:
- Check [docs/HYBRID_ROUTING.md](docs/HYBRID_ROUTING.md) for detailed usage
- Verify environment variables are set correctly
- Ensure endpoint index is up to date

