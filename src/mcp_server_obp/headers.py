import os
from fastmcp import Context
from fastmcp.server.dependencies import get_access_token
from dotenv import load_dotenv
from mcp_server_obp.elicitation import elicit_consent
from src.tools import EndpointSchema

load_dotenv()

async def construct_obp_headers(ctx: Context, headers: dict, endpoint: EndpointSchema) -> dict:
    """
    Construct headers for OBP API requests, eliciting user consent if necessary.
    """
    authorization_method = os.getenv("OBP_AUTHORIZATION_VIA", "none").lower()
    if not authorization_method in ["oauth", "consent", "none"]:
        raise ValueError(f"Invalid OBP_AUTHORIZATION_VIA value: {authorization_method}")
    
    if authorization_method == "oauth":
        # Use OAuth access token from context
        access_token = get_access_token()
        if not access_token:
            raise ValueError("No access token available in context for OAuth authorization.")
        
        obp_headers = {
            **headers,
            "Authorization": f"Bearer {access_token}"
        }
        return obp_headers
    elif authorization_method == "consent":
        # Elicit user consent for the endpoint
        consent_response = await elicit_consent(ctx, endpo)