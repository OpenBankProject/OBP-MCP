""" Client for testing Keycloak OAuth authentication with FastMCP. """
from fastmcp import Client
import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

async def main():
    # The client will automatically handle Keycloak OAuth
    async with Client(f"{os.getenv("BASE_URL")}/mcp", auth="oauth") as client:
        # First-time connection will open Keycloak login in your browser
        print("✓ Authenticated with Keycloak!")

        # Test the protected tool
        result = await client.call_tool("get_access_token_claims")
        print(f"User: {result.data.get('preferred_username', 'N/A')}")

if __name__ == "__main__":
    asyncio.run(main())