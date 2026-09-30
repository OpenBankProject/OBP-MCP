# OBP-MCP

MCP Server for the Open Bank Project API - enables AI assistants to interact with 600+ OBP API endpoints via tag-based routing and glossary access.

## Architecture

![How Opey, Claude Code and OBP-MCP call OBP-API](https://github.com/user-attachments/assets/d3ff5c10-7167-4034-98f7-c53a323bf985)

Top to bottom: users reach OBP through the OBP-Portal / API Explorer II frontend, which talks to [Opey](https://github.com/OpenBankProject/OBP-Opey-II); Opey and external MCP clients (Claude Code, Claude Desktop, IDE agents) call OBP-MCP over MCP/HTTP; OBP-MCP makes the authenticated HTTPS calls to OBP-API, which in turn reaches core banking systems via its southbound connectors. OBP-OIDC issues and validates the tokens used at each hop. The numbered orange flow shows how user consent is obtained when a tool call requires a `Consent-JWT`: OBP-MCP returns `consent_required`, Opey surfaces it to the frontend as an SSE event, the frontend creates an implicit consent on OBP-API, and the tool call is retried with the `Consent-JWT` header.

Opey also makes some direct (non-MCP) HTTP calls to OBP-API for its own infrastructure — session validation, admin operations, checkpoint persistence and health probes — covered by a separate detail diagram.

The editable masters live in Lucidchart: [architecture overview](https://lucid.app/lucidchart/3ee12366-1269-49a9-9f6a-b2f5eb70d59a/edit) · [Opey direct-HTTP detail](https://lucid.app/lucidchart/fe000bca-db8e-4179-bf84-e80e79ba861e/edit). To update the image: edit the Lucid doc, export the page as PNG, upload it to a GitHub issue comment, and replace the `github.com/user-attachments/assets/...` URL here (and in the Opey README and the OBP-API glossary, which embed the same image).

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
OBP_VERSION_TO_CALL=v7.0.0
API_VERSION_OF_INTEREST=v7.0.0
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

Two separate settings control auth. Don't mix them up — both can involve OAuth:

| Setting | Controls | Values |
| --- | --- | --- |
| `AUTH_PROVIDER` (with `ENABLE_OAUTH`) | How a client **connects to this MCP server** | `bearer-only`, `obp-oidc`, `keycloak`, or off |
| `OBP_AUTHORIZATION_VIA` | How this server's **calls to OBP-API** are authorized | `consent` (**Consent mode**) or `oauth` (**OAuth mode**) |

- **Consent mode** — every call to OBP-API carries a `Consent-JWT` supplied by the client with the tool call. Any `Authorization` header from the client is dropped. Without a Consent-JWT, calls to non-public endpoints return `consent_required`. Use this for Opey.
- **OAuth mode** — every call to OBP-API carries the OAuth access token the user logged in to this MCP server with. Use this for Claude Code, Claude Desktop, VS Code and other general MCP clients.
- Any other value (including unset): the server starts, logs a prominent warning, and `call_obp_api` refuses every request.

The server's home page (`/`) and `/status` page show which mode it is in at the top, and `/status?format=json` reports it as `auth.mode`.

### Connecting to the MCP server

OBP-MCP supports three connection authentication providers:

| Mode            | Use Case                                       | `AUTH_PROVIDER` |
| --------------- | ---------------------------------------------- | --------------- |
| **bearer-only** | Internal agents (Opey), microservices          | `bearer-only`   |
| **obp-oidc**    | External MCP clients (VS Code, Claude Desktop) | `obp-oidc`      |
| **keycloak**    | External MCP clients with Keycloak             | `keycloak`      |

#### For Opey (Internal Agent)

Use `bearer-only` authentication together with Consent mode (full setup in [Appendix 1](#appendix-1---opey-setup)). This mode:

- **Does NOT** expose OAuth discovery endpoints
- Simply validates JWT tokens against OBP-OIDC's JWKS
- Is designed for architectures where OAuth is handled externally (e.g., by a frontend portal)

```bash
# .env
ENABLE_OAUTH="true"
AUTH_PROVIDER=bearer-only
OBP_OIDC_ISSUER_URL=http://localhost:9000/obp-oidc
OBP_AUTHORIZATION_VIA="consent"
```

Opey authenticates to the MCP server with **its own** client-credentials token, not the user's token. The user's identity travels only in the per-call `Consent-JWT`:

```
Authorization: Bearer <Opey's client-credentials token>
```

#### For External MCP Clients (VS Code, Claude Desktop, MCP Inspector)

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

#### Disabling Authentication

For development or testing without authentication:

```bash
ENABLE_OAUTH="false"
```

This only turns off login for connecting to the MCP server. Calls to OBP-API still follow `OBP_AUTHORIZATION_VIA`. Note that OAuth mode with login turned off has no user token to send, so OBP-API calls go out without one.

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

## Appendix 1 - Opey setup

Opey-II uses **Consent mode**. Opey authenticates to OBP-MCP with its own client-credentials token (service identity), and passes the user's `Consent-JWT` with each tool call (user identity). The user's own OAuth token never reaches OBP-MCP.

OBP-MCP `.env`:

```bash
ENABLE_OAUTH="true"
AUTH_PROVIDER=bearer-only
OBP_OIDC_ISSUER_URL=http://localhost:9000/obp-oidc
OBP_AUTHORIZATION_VIA="consent"
OBP_OPEY_CONSUMER_KEY=<opey's consumer key (same as the OBP_CONSUMER_KEY in Opey)>
```

In Opey's `mcp_servers.json` (inside the servers array):

```json
{
      "name": "obp",
      "url": "http://0.0.0.0:9100/mcp",
      "transport": "http",
      "use_service_token": true
}
```

And in Opey's `.env`, the credentials Opey uses to get its service token from OBP-OIDC (all three are required, otherwise Opey sends no `Authorization` header):

```bash
OPEY_OIDC_TOKEN_URL=http://localhost:9000/obp-oidc/token
OPEY_OIDC_CLIENT_ID=<opey's OIDC client id>
OPEY_OIDC_CLIENT_SECRET=<opey's OIDC client secret>
```

> [!NOTE] `forward_bearer_token: true` (which forwarded the user's own OAuth token to OBP-MCP) is the older setup and should no longer be used with Consent mode. In Consent mode OBP-MCP ignores that token for OBP calls anyway.

> [!WARNING] `bearer-only` requires the scopes `openid`, `profile` and `email` in every token by default. Opey currently requests its client-credentials token without a `scope` parameter, and OBP-OIDC then issues it with an empty scope, so OBP-MCP will reject it. Until that is resolved, a local setup can run with `ENABLE_OAUTH="false"` (no login needed to connect; OBP calls are still protected by the Consent-JWT).

> [!NOTE] A server in Consent mode is not useful to general MCP clients (Claude Code, VS Code, …): they can connect and use the discovery and glossary tools, but `call_obp_api` returns `consent_required` because they can't create consents. Run a second instance in OAuth mode for those clients.

## Appendix 2 - End user addresses (X-Forwarded-For)

OBP-API applies per-address rate limits and penalties to the address of whoever calls it. So that it sees the end user rather than this server, every hop in front of OBP-API appends to `X-Forwarded-For` the address it received the request from. OBP-MCP sends on the `X-Forwarded-For` the MCP client put in the tool call's `headers`, followed by the `X-Forwarded-For` of the MCP HTTP request (set by a proxy in front of OBP-MCP, if there is one) and the TCP peer of that request. It removes any `X-Real-IP` or `Forwarded` the caller supplied. Over the stdio transport there is no peer to vouch for the chain, so no `X-Forwarded-For` is sent.

OBP-API reads the chain from the right and skips the addresses it trusts, so the first address it does not trust is the client. For the chain to be believed, OBP-API's props must list this server's address, and every hop in front of it (for example NGINX, API Explorer II and Opey):

```properties
trust.proxy.enabled=true
trust.proxy.header=X-Forwarded-For
trust.proxy.peers=<OBP-MCP address>, <Opey address>, <API Explorer II address>, <NGINX address>
```

An MCP client that is not in that list becomes the client itself, so it cannot name another address. OBP-MCP starts Uvicorn with `proxy_headers` turned off so that the TCP peer it appends is the real socket peer.

## License

AGPLv3
