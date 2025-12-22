#!/bin/bash

# OBP-MCP HTTP Server Startup Script

# Load .env file if it exists
if [ -f .env ]; then
    echo "Loading environment from .env file..."
    # Export all variables from .env file
    set -a
    source .env
    set +a
fi

# Set default values if not already set
# FastMCP uses FASTMCP_HOST and FASTMCP_PORT environment variables
export FASTMCP_HOST=${FASTMCP_HOST:-0.0.0.0}
export FASTMCP_PORT=${FASTMCP_PORT:-9100}
export OBP_BASE_URL=${OBP_BASE_URL:-https://apisandbox.openbankproject.com}
export OBP_API_VERSION=${OBP_API_VERSION:-v5.1.0}

# Parse command line arguments
WATCH_MODE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --watch|-w)
            WATCH_MODE=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--watch|-w]"
            echo "  --watch, -w    Enable watch mode (auto-reload on file changes)"
            exit 1
            ;;
    esac
done

echo "=========================================="
echo "Starting OBP-MCP HTTP Server"
echo "=========================================="
echo "Host: $FASTMCP_HOST"
echo "Port: $FASTMCP_PORT"
echo "OBP Base URL: $OBP_BASE_URL"
echo "OBP API Version: $OBP_API_VERSION"
if [ "$WATCH_MODE" = true ]; then
    echo "Watch Mode: ENABLED (auto-reload on changes)"
fi
echo "=========================================="
echo ""
echo "Server will be available at: http://$FASTMCP_HOST:$FASTMCP_PORT"
echo "MCP endpoint: http://$FASTMCP_HOST:$FASTMCP_PORT/mcp/v1"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the server using uv
if [ "$WATCH_MODE" = true ]; then
    # Install watchfiles if not already installed
    uv pip list | grep -q watchfiles || uv pip install watchfiles
    
    # Watch mode: monitor src/ and database/ directories
    uv run watchfiles \
        --ignore-paths 'database/data/*' \
        --ignore-paths '__pycache__' \
        --ignore-paths '*.pyc' \
        'uv run python src/mcp_server_obp/server.py' \
        src/ \
        database/*.py \
        database/*.json
else
    # Normal mode
    uv run python src/mcp_server_obp/server.py
fi
