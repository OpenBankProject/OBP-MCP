import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Any
from database.startup_updater import update_index_on_startup

logger = logging.getLogger(__name__)

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
    
    # Check and update index on startup
    success = await update_index_on_startup()
    if not success:
        logger.error("Index update on startup failed.")
    else:
        logger.info("Index update on startup completed successfully.")
    
    yield {}  # Application runs here - return empty dict as lifespan result
    
    # Shutdown actions
    logger.info("Shutting down MCP server...")