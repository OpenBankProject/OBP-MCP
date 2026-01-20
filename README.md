# OBP-MCP
MCP Server for the Open Bank Project API - enables AI assistants to interact with 600+ OBP API endpoints via tag-based routing and glossary access.

## Quick Start

### Install uv

**MacOS/Linux:**
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```


### Setup

1. Create `.env` file:
```bash
OBP_BASE_URL=https://apisandbox.openbankproject.com
OBP_API_VERSION=v5.1.0
FASTMCP_HOST=127.0.0.1
FASTMCP_PORT=9100
```

2. Generate indexes:
```bash
uv run python scripts/generate_endpoint_index.py
uv run python scripts/generate_glossary_index.py
```

3. Run server:
```bash
uv sync
./run_server.sh
```

Server starts at `http://0.0.0.0:9100`

## Testing with MCP Inspector

Run the server normally then start the inspector with:
```bash
npx @modelcontextprotocol/inspector \
```

You can then configure the connection to the server from there.


## Client Integration

### VS Code

Configure in `~/.config/Code/User/mcp.json`:
```json
{
  "mcpServers": {
    "obp-mcp": {
      "url": "http://0.0.0.0:9100/mcp",
      "type": "http"
    }
  }
}
```

### Zed

Configure in `~/.config/zed/settings.json`:
```json
{
  "context_servers": {
    "obp-mcp": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:9100/mcp"]
    }
  }
}
```

## Available Tools

**Endpoint Tools:**
- `list_endpoints_by_tag` - Filter 600+ endpoints by category
- `get_endpoint_schema` - Fetch full OpenAPI schema
- `call_obp_api` - Execute API requests

**Glossary Tools:**
- `list_glossary_terms` - Search 800+ OBP terms
- `get_glossary_term` - Get full definitions

See [docs/HYBRID_ROUTING.md](docs/HYBRID_ROUTING.md) for details.

## License

AGPLv3
