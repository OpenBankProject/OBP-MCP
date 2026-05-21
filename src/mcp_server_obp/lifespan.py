import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Any
from database.startup_updater import update_index_on_startup

logger = logging.getLogger(__name__)

_VALID_OUTBOUND_AUTH = {"oauth", "consent"}


def _validate_outbound_auth() -> None:
    """Fail loudly at startup if OBP_AUTHORIZATION_VIA isn't oauth or consent.

    The previous 'none' mode let call_obp_api fire unauthenticated requests
    against OBP-API, which severed the link between a chat session and an
    identified OBP user. Requiring an explicit mode here makes that
    impossible by construction.
    """
    value = os.getenv("OBP_AUTHORIZATION_VIA", "").lower()
    if value not in _VALID_OUTBOUND_AUTH:
        raise RuntimeError(
            f"OBP_AUTHORIZATION_VIA must be one of {sorted(_VALID_OUTBOUND_AUTH)}; "
            f"got {value!r}. Refusing to start — unauthenticated OBP-API access is "
            "no longer supported."
        )


def print_client_configs():
    """Print copy-pasteable MCP client configuration snippets."""
    host = os.getenv("FASTMCP_HOST", "127.0.0.1")
    port = os.getenv("FASTMCP_PORT", "9100")
    auth_provider = os.getenv("AUTH_PROVIDER", "none")
    requires_auth = auth_provider != "none"
    base_url = f"http://{host}:{port}/mcp"

    configs = {
        "Opey": {
            "servers": [
                {
                    "name": "obp",
                    "url": base_url,
                    "transport": "http",
                    "requires_auth": requires_auth,
                }
            ]
        },
        "Claude Desktop / claude_desktop_config.json": {
            "mcpServers": {
                "obp": {
                    "url": base_url,
                }
            }
        },
        "VS Code / settings.json": {
            "mcp": {
                "servers": {
                    "obp": {
                        "url": base_url,
                    }
                }
            }
        },
    }

    separator = "=" * 60
    print(f"\n{separator}")
    print("MCP Client Configurations")
    print(separator)
    for name, config in configs.items():
        print(f"\n--- {name} ---\n")
        print(json.dumps(config, indent=2))
    print(f"\n{separator}\n")


async def periodic_index_refresh(interval_minutes: int):
    """Periodically check and update the index every N minutes."""
    interval_seconds = interval_minutes * 60
    while True:
        try:
            await asyncio.sleep(interval_seconds)
            logger.info("Periodic index refresh: checking for updates...")
            success = await update_index_on_startup()
            if success:
                logger.info("Periodic index refresh completed successfully")
            else:
                logger.warning("Periodic index refresh failed")
        except asyncio.CancelledError:
            logger.info("Periodic index refresh task cancelled")
            break
        except Exception as e:
            logger.error(f"Error in periodic index refresh: {e}")
            # Continue loop - don't crash on transient errors

@asynccontextmanager
async def lifespan(server) -> AsyncIterator[dict[str, Any]]:
    """
    Lifespan context manager to handle startup and shutdown events.
    
    On startup, it checks for OBP data changes and updates the index if needed.
    
    Args:
        server: The FastMCP server instance this lifespan is managing
    
    Returns:
        An empty dictionary as the lifespan result
    """
    # Startup actions
    logger.info("Starting MCP server...")
    _validate_outbound_auth()
    print_client_configs()

    # Check and update index on startup
    success = await update_index_on_startup()
    if not success:
        logger.error("Index update on startup failed.")
    else:
        logger.info("Index update on startup completed successfully.")

    # Start periodic refresh task if enabled
    refresh_task = None
    interval = int(os.getenv("REFRESH_INTERVAL_MINUTES", "5"))
    if interval > 0:
        refresh_task = asyncio.create_task(periodic_index_refresh(interval))
        logger.info(f"Periodic index refresh enabled: every {interval} minutes")
    else:
        logger.info("Periodic index refresh disabled (REFRESH_INTERVAL_MINUTES <= 0)")

    yield {}  # Application runs here - return empty dict as lifespan result

    # Shutdown actions
    logger.info("Shutting down MCP server...")

    # Cancel periodic refresh task if running
    if refresh_task and not refresh_task.done():
        refresh_task.cancel()
        try:
            await refresh_task
        except asyncio.CancelledError:
            pass