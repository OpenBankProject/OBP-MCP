#!/bin/bash

# OBP-MCP HTTP Server Startup Script — OAuth instance (mirrors k8s-mcp2)
# Uses .env.oauth; the default instance for Opey uses .env via run_server.sh.

if [ ! -f .env.oauth ]; then
    echo "ERROR: .env.oauth not found. Copy and adapt it from .env."
    exit 1
fi

echo "Loading environment from .env.oauth file..."
set -a
source .env.oauth
set +a

export FASTMCP_HOST=${FASTMCP_HOST:-127.0.0.1}
export FASTMCP_PORT=${FASTMCP_PORT:-9101}

echo "=========================================="
echo "Starting OBP-MCP HTTP Server (OAuth instance)"
echo "=========================================="
echo "Host: $FASTMCP_HOST"
echo "Port: $FASTMCP_PORT"
echo "OBP Base URL: $OBP_BASE_URL"
echo "Auth provider: $AUTH_PROVIDER"
echo "OIDC issuer: $OBP_OIDC_ISSUER_URL"
echo "=========================================="
echo ""
echo "MCP endpoint: http://$FASTMCP_HOST:$FASTMCP_PORT/mcp"
echo "Status page:  http://$FASTMCP_HOST:$FASTMCP_PORT/status"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

uv run python src/mcp_server_obp/server.py
