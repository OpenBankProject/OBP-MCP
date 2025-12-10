#!/bin/bash

# OBP-MCP HTTP Server Startup Script

# Set default values if not already set
export MCP_SERVER_HOST=${MCP_SERVER_HOST:-0.0.0.0}
export MCP_SERVER_PORT=${MCP_SERVER_PORT:-8000}
export OBP_BASE_URL=${OBP_BASE_URL:-https://apisandbox.openbankproject.com}
export OBP_API_VERSION=${OBP_API_VERSION:-v5.1.0}

echo "=========================================="
echo "Starting OBP-MCP HTTP Server"
echo "=========================================="
echo "Host: $MCP_SERVER_HOST"
echo "Port: $MCP_SERVER_PORT"
echo "OBP Base URL: $OBP_BASE_URL"
echo "OBP API Version: $OBP_API_VERSION"
echo "=========================================="
echo ""
echo "Server will be available at: http://$MCP_SERVER_HOST:$MCP_SERVER_PORT"
echo "MCP endpoint: http://$MCP_SERVER_HOST:$MCP_SERVER_PORT/mcp/v1"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server using uv
uv run python src/mcp_server_obp/server.py
