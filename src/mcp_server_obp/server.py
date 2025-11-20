from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Open Bank Project")

@mcp.tool
async def retrieve_endpoints(query: str) -> str:
    """Retrieve Relevant Open Bank Project API Endpoints based on a query."""
    