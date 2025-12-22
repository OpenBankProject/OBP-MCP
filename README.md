# OBP-MCP
An MCP Server for the Open Bank Project (OBP) API

## Overview

OBP-MCP provides a Model Context Protocol (MCP) server that enables AI assistants to interact with the Open Bank Project API. It features a hybrid tag-based endpoint routing system designed for efficiency and cost-effectiveness when working with 600+ API endpoints.

## Features

- **🚀 Tag-Based Routing**: Fast, cost-effective endpoint discovery
- **📊 Lightweight Indexes**: Minimal token usage with on-demand schema loading
- **🔧 Core Endpoint Tools**:
  - `list_endpoints_by_tag` - Discover endpoints by category
  - `get_endpoint_schema` - Fetch full OpenAPI schemas on-demand
  - `call_obp_api` - Execute API requests with validation
- **📚 Glossary Tools**: Access 800+ OBP term definitions
  - `list_glossary_terms` - Search and list glossary terms
  - `get_glossary_term` - Get full term definitions
- **🔄 MCP Resources**: URI-based access to glossary terms

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

### Generate Endpoint and Glossary Indexes

Generate the lightweight endpoint index from the OBP API:

```bash
uv run python scripts/generate_endpoint_index.py
```

This creates `database/endpoint_index.json` with endpoint summaries.

Generate the glossary index:

```bash
uv run python scripts/generate_glossary_index.py
```

This creates `database/glossary_index.json` with glossary term definitions.

### Running the Server

#### Option 1: HTTP Server (Recommended)

Run the server as an HTTP service:

```bash
# Install dependencies
uv sync

# Quick start with default settings (recommended)
./run_server.sh

# Development mode with auto-reload on file changes
./run_server.sh --watch
```

The server will start on `http://0.0.0.0:8000` by default. You can customize the configuration:

```bash
# Custom host and port
export MCP_SERVER_HOST=127.0.0.1
export MCP_SERVER_PORT=9100
./run_server.sh

# Or run directly with Python
python src/mcp_server_obp/server.py
```

#### Option 2: VS Code Integration

First, start the HTTP server:
```bash
./run_server.sh
```

Then configure the server in your VS Code MCP settings (`~/.config/Code/User/mcp.json`):

```json
{
  "mcpServers": {
    "obp-mcp": {
			"url": "http://0.0.0.0:8000/mcp",
			"type": "http"
		}
  }
}
```

For reference, see the example configuration in `.vscode/mcp.json.example`.

## Usage

### Endpoint Tools

#### Tool 1: List Endpoints by Tag

Discover endpoints filtered by tags:

```python
list_endpoints_by_tag(["Account", "Transaction"])
```

Returns lightweight summaries (id, method, path, summary, tags) without full schemas.

#### Tool 2: Get Endpoint Schema

Fetch the full OpenAPI schema for a specific endpoint:

```python
get_endpoint_schema("vVERSION-getBanks")
```

#### Tool 3: Call OBP API

Execute an API request:

```python
call_obp_api(
    "vVERSION-privateAccountsAtOneBank",
    path_params={"BANK_ID": "gh.29.uk"},
    headers={"Authorization": "DirectLogin token=..."}
)
```

### Glossary Tools

Access OBP glossary terms (800+ definitions):

#### List Glossary Terms

Search and list glossary terms:

```python
list_glossary_terms()  # List all terms
list_glossary_terms("oauth")  # Search for OAuth-related terms
```

Returns a lightweight list with term IDs and titles.

#### Get Glossary Term

Get the full definition of a specific term:

```python
get_glossary_term("oauth")  # Get OAuth definition
get_glossary_term("account-account-id")  # Get Account ID definition
```

Returns the complete term with markdown and HTML descriptions.

### Glossary Resources

Access OBP glossary terms via MCP resources (for clients that support resources):

#### List All Glossary Terms

Access `obp://glossary` to get all 800+ glossary terms with IDs and titles.

#### Get Specific Term

Access `obp://glossary/{term_id}` to get a specific term's full definition with markdown and HTML descriptions.

Examples:
- `obp://glossary/account-account-id` - Account ID definition
- `obp://glossary/api` - API definition
- `obp://glossary/bank-bank-id` - Bank ID definition

## Documentation

- **[Hybrid Routing Guide](docs/HYBRID_ROUTING.md)** - Detailed architecture and usage

## Architecture

The system uses lightweight JSON indexes for fast lookups:

1. **Tag-Based Discovery** - Filter 600+ endpoints by category tags
2. **Lightweight Index** - Minimal endpoint summaries (id, method, path, tags)
3. **On-Demand Schema** - Load full OpenAPI schemas only when needed
4. **Glossary Index** - Fast lookup of 800+ OBP term definitions

See [docs/HYBRID_ROUTING.md](docs/HYBRID_ROUTING.md) for complete details.

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

AGPLv3

## Support

For issues or questions:
- Check [docs/HYBRID_ROUTING.md](docs/HYBRID_ROUTING.md) for detailed usage
- Verify environment variables are set correctly
- Ensure endpoint index is up to date
