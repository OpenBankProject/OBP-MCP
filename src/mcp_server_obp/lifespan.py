import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator, Any
from database.startup_updater import update_index_on_startup

logger = logging.getLogger(__name__)

_VALID_OUTBOUND_AUTH = {"oauth", "consent"}

# Hosts for which serving without client authentication is acceptable: the
# server is only reachable from the local machine.
_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", ""}


def _warn_if_outbound_auth_invalid() -> None:
    """Log a prominent warning — but do NOT refuse to start — if
    OBP_AUTHORIZATION_VIA isn't 'oauth' or 'consent'.

    call_obp_api itself still refuses to make a request in any other mode (it
    returns an 'OBP-API calls are disabled' error), so unauthenticated OBP-API
    access cannot happen regardless. This only surfaces the misconfiguration at
    startup instead of leaving it to be discovered when the first tool call
    fails.
    """
    value = os.getenv("OBP_AUTHORIZATION_VIA", "").lower()
    if value in _VALID_OUTBOUND_AUTH:
        return
    logger.warning(
        "\n"
        "########################################################################\n"
        "#  CONFIG WARNING: OBP_AUTHORIZATION_VIA is not 'oauth' or 'consent'.  #\n"
        "#  call_obp_api will refuse every request until this is set — OBP-API  #\n"
        "#  calls are disabled in this state.                                   #\n"
        "########################################################################\n"
        "  OBP_AUTHORIZATION_VIA=%r",
        value,
    )


def _inbound_auth_configured() -> bool:
    """Mirror get_auth_provider()'s gating: return True iff client-to-MCP
    authentication is active.

    auth is disabled (get_auth_provider returns None) when ENABLE_OAUTH is not
    'true' or when AUTH_PROVIDER is 'none'. Kept in sync with auth.py's two
    None-return paths.
    """
    if os.getenv("ENABLE_OAUTH", "false").lower() != "true":
        return False
    return os.getenv("AUTH_PROVIDER", "keycloak").lower() != "none"


def _warn_if_inbound_auth_missing() -> None:
    """Log a prominent warning — but do NOT refuse to start — when the server is
    bound to a non-loopback interface with no client authentication.

    With auth disabled, FastMCP serves every tool to anyone who can reach the
    port, turning OBP-MCP into an open, unauthenticated proxy in front of
    OBP-API. OBP-API still enforces its own per-endpoint authentication and
    consent, so this is not by itself a data breach — an anonymous caller can
    only reach what OBP-API already exposes anonymously — but an open proxy
    invites abuse and request amplification and departs from the intended auth
    posture. On loopback this is fine and we stay quiet. On a public interface
    we log a loud warning so it cannot go unnoticed; set
    ALLOW_UNAUTHENTICATED_PUBLIC=true to acknowledge and silence it (e.g. when
    authentication is terminated by an upstream proxy).
    """
    if _inbound_auth_configured():
        return

    host = os.getenv("FASTMCP_HOST", "127.0.0.1").strip().lower()
    if host in _LOOPBACK_HOSTS:
        return  # loopback-only; unauthenticated is fine for local use

    if os.getenv("ALLOW_UNAUTHENTICATED_PUBLIC", "").lower() == "true":
        logger.info(
            "OBP-MCP is bound to %r with no client authentication, by explicit "
            "opt-in (ALLOW_UNAUTHENTICATED_PUBLIC=true). Ensure authentication is "
            "enforced upstream.",
            host,
        )
        return

    logger.warning(
        "\n"
        "########################################################################\n"
        "#  SECURITY WARNING: OBP-MCP is running with NO client authentication  #\n"
        "#  on a non-loopback (public-facing) interface.                        #\n"
        "#  Every MCP tool, including call_obp_api, is reachable by anyone who  #\n"
        "#  can reach this port. OBP-API still enforces its own per-endpoint    #\n"
        "#  auth, but this runs OBP-MCP as an OPEN PROXY.                       #\n"
        "#  Fix: set ENABLE_OAUTH=true + AUTH_PROVIDER=obp-oidc (or keycloak),  #\n"
        "#  or bind FASTMCP_HOST=127.0.0.1. Set ALLOW_UNAUTHENTICATED_PUBLIC=   #\n"
        "#  true to acknowledge and silence this warning.                       #\n"
        "########################################################################\n"
        "  FASTMCP_HOST=%s",
        host,
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
    _warn_if_outbound_auth_invalid()
    _warn_if_inbound_auth_missing()
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