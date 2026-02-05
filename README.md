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

## Authentication

OBP-MCP supports three authentication modes:

| Mode            | Use Case                                       | `AUTH_PROVIDER` |
| --------------- | ---------------------------------------------- | --------------- |
| **bearer-only** | Internal agents (Opey), microservices          | `bearer-only`   |
| **obp-oidc**    | External MCP clients (VS Code, Claude Desktop) | `obp-oidc`      |
| **keycloak**    | External MCP clients with Keycloak             | `keycloak`      |

### For Opey (Internal Agent)

Use `bearer-only` authentication. This mode:

- **Does NOT** expose OAuth discovery endpoints
- Simply validates JWT tokens against OBP-OIDC's JWKS
- Is designed for architectures where OAuth is handled externally (e.g., by a frontend portal)

```bash
# .env
ENABLE_OAUTH="true"
AUTH_PROVIDER=bearer-only
OBP_OIDC_ISSUER_URL=http://localhost:9000/obp-oidc
```

Your agent passes the user's access token with each MCP request:

```
Authorization: Bearer <user_access_token>
```

### For External MCP Clients (VS Code, Claude Desktop, MCP Inspector)

Use `obp-oidc` or `keycloak` authentication. These modes expose the full OAuth 2.1 discovery flow, allowing MCP clients to:

- Discover authorization endpoints via `/.well-known/oauth-protected-resource`
- Perform Dynamic Client Registration (RFC 7591)
- Complete the OAuth authorization code flow with PKCE

```bash
# .env
ENABLE_OAUTH="true"
AUTH_PROVIDER=obp-oidc
OBP_OIDC_ISSUER_URL=http://localhost:9000/obp-oidc
BASE_URL=http://localhost:9100
```

### Disabling Authentication

For development or testing without authentication:

```bash
ENABLE_OAUTH="false"
```

for more information about auth and how to configure your OIDC providers see the [docs](docs/AUTH_SETUP.md).

## Testing with MCP Inspector

Run the server normally then start the inspector with:

```bash
npx @modelcontextprotocol/inspector \
```

You can then configure the connection to the server from there.

## Client Integration

### VS Code

Configure in the servers section of `~/.config/Code/User/mcp.json`:

```json
{
  "servers": {
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

### Claude (code)

Configure in ~/.claude.json. The relevant section is:

```json

  "mcpServers": {
    "obp-mcp": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:9100/mcp"
      ],
      "env": {}
    }
  }

```

This is a global config that makes the obp-mcp server available to all projects. It connects to http://127.0.0.1:9100/mcp using mcp-remote.

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
