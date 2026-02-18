import sys
import logging
import os
import json
import requests
from pathlib import Path
from typing import List
from dotenv import load_dotenv

# Load environment variables from .env file before anything else
load_dotenv()

# Configure logging (allow override via LOG_LEVEL env)
_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
# Ensure our package logger honors the chosen level (basicConfig locks in handlers)
logging.getLogger("mcp_server_obp").setLevel(getattr(logging, _log_level, logging.INFO))

# Add the src and project root directories to the Python path when running as a script
_src_dir = Path(__file__).parent.parent
_project_root = _src_dir.parent
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from fastmcp import FastMCP, Context
from fastmcp.server.dependencies import get_access_token

from src.tools.endpoint_index import get_endpoint_index
from src.tools.glossary_index import get_glossary_index

from mcp_server_obp.lifespan import lifespan
from mcp_server_obp.auth import get_auth_provider

logger = logging.getLogger(__name__)

# Initialize authentication provider based on environment configuration
# Supports: keycloak, obp-oidc, or none (disabled)
# See auth.py for configuration details
auth = get_auth_provider()



mcp = FastMCP(
    "Open Bank Project",
    auth=auth,
    lifespan=lifespan
)



# ============================================================================
# NEW HYBRID TAG-BASED ENDPOINT TOOLS (RECOMMENDED)
# ============================================================================

@mcp.tool()
def list_all_endpoint_tags() -> str:
    """
    Get all available OBP API endpoint tags.
    
    Use this to discover what tags are available before calling list_endpoints_by_tag().
    Tags represent different categories of endpoints (e.g., "Account", "Transaction", "Customer").
    
    Returns:
        JSON string with all available tags and their endpoint counts
    
    Example:
        list_all_endpoint_tags() -> Returns all available tags with counts
    """
    try:
        index = get_endpoint_index()
        tags = index.get_all_tags()
        
        # Count endpoints per tag
        tag_counts = {}
        for tag in tags:
            endpoints = index.list_endpoints_by_tag([tag])
            tag_counts[tag] = len(endpoints)
        
        # Sort by count descending
        sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)
        
        return json.dumps({
            "total_tags": len(tags),
            "tags": [{"tag": tag, "endpoint_count": count} for tag, count in sorted_tags]
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error listing endpoint tags: {e}")
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def list_endpoints_by_tag(tags: List[str]) -> str:
    """
    Get available OBP API endpoints for given tags. Returns lightweight summaries (no full schemas).
    
    This is the recommended first step for discovering relevant endpoints. Use this to get a list
    of endpoints matching certain categories, then use get_endpoint_schema() to fetch full details
    for specific endpoints.
    
    Args:
        tags: List of tag names to filter endpoints (e.g., ["Account", "Transaction", "Customer"])
              If empty, returns all available endpoints.
    
    Returns:
        JSON string with endpoint summaries including: id, method, path, operation_id, summary, tags
    
    Example:
        list_endpoints_by_tag(["Account", "Bank"]) -> Returns all endpoints tagged with Account or Bank
    """
    try:
        index = get_endpoint_index()
        endpoints = index.list_endpoints_by_tag(tags)
        
        if not endpoints:
            return json.dumps({
                "message": f"No endpoints found for tags: {tags}",
                "available_tags": index.get_all_tags()[:20],  # Show first 20 tags as hints
                "total_endpoints": len(index._index)
            }, indent=2)
        
        # Serialize Pydantic models to dictionaries
        return json.dumps({
            "count": len(endpoints),
            "endpoints": [ep.model_dump() for ep in endpoints]
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error listing endpoints by tag: {e}")
        return json.dumps({"error": str(e)}, indent=2)

# Should only be use for testing/debugging oauth. Returns token claims, i.e. verifying that a user has authenticated.
# @mcp.tool
# async def get_access_token_claims() -> dict:
#     """Get the authenticated user's access token claims."""
#     token = get_access_token()
#     return {
#         "sub": token.claims.get("sub"),
#         "name": token.claims.get("name"),
#         "preferred_username": token.claims.get("preferred_username"),
#         "scope": token.claims.get("scope")
#     }

@mcp.tool()
def get_endpoint_schema(endpoint_id: str) -> str:
    """
    Get the full OpenAPI schema for a specific OBP API endpoint.
    
    Use this after identifying the endpoint you need via list_endpoints_by_tag().
    This fetches the complete endpoint specification including parameters, request/response schemas,
    and descriptions.
    
    Args:
        endpoint_id: The unique identifier of the endpoint (from list_endpoints_by_tag results)
    
    Returns:
        JSON string with full endpoint schema including all parameters and documentation
    
    Example:
        get_endpoint_schema("GET-obp-vVERSION-users-current") -> Full schema for current user endpoint
    """
    try:
        index = get_endpoint_index()
        schema = index.get_endpoint_schema(endpoint_id)
        
        if not schema:
            return json.dumps({
                "error": f"Endpoint '{endpoint_id}' not found",
                "suggestion": "Use list_endpoints_by_tag() to find available endpoints"
            }, indent=2)
        
        # Serialize Pydantic model to dictionary
        return json.dumps(schema.model_dump(by_alias=True), indent=2)
        
    except Exception as e:
        logger.error(f"Error getting endpoint schema: {e}")
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
async def call_obp_api(
    ctx: Context,
    endpoint_id: str,
    path_params: dict = {},
    query_params: dict = {},
    body: dict = {},
    headers: dict = {}
) -> str:
    """
    Execute an OBP API request to a specific endpoint.
    
    Uses the lightweight endpoint index to construct and execute the API call.
    Requires OBP_BASE_URL and OBP_API_VERSION environment variables to be set.
    You may also need authentication headers depending on the endpoint.
    
    Args:
        endpoint_id: The unique identifier of the endpoint (operation_id from list_endpoints_by_tag)
        path_params: Dictionary of path parameters (e.g., {"BANK_ID": "gh.29.uk"})
        query_params: Dictionary of query parameters (e.g., {"limit": 10})
        body: Request body as dictionary (for POST/PUT requests)
        headers: Additional HTTP headers (e.g., {"Authorization": "DirectLogin token=..."})
    
    Returns:
        JSON string with API response or error details
    
    Example:
        call_obp_api("OBPv4.0.0-getBanks") -> Get list of banks
    """
    try:
        index = get_endpoint_index()
        
        # Get endpoint info from lightweight index
        endpoint = index.get_endpoint_schema(endpoint_id)
        if not endpoint:
            return json.dumps({
                "error": f"Endpoint '{endpoint_id}' not found",
                "suggestion": "Use list_endpoints_by_tag() to find available endpoints"
            }, indent=2)
        
        # Build the request URL
        base_url = os.getenv("OBP_BASE_URL")
        api_version = os.getenv("OBP_API_VERSION")
        
        if not base_url or not api_version:
            return json.dumps({
                "error": "OBP_BASE_URL and OBP_API_VERSION environment variables must be set"
            }, indent=2)
        
        # Construct the path with parameters
        path = endpoint.path
        if path_params:
            for key, value in path_params.items():
                # OBP index stores path params as bare names (e.g. USER_ID),
                # but OpenAPI standard uses {USER_ID}. Handle both.
                path = path.replace(f"{{{key}}}", str(value))
                path = path.replace(key, str(value))
        
        # Replace VERSION placeholder
        path = path.replace("VERSION", api_version)
        
        # Build full URL
        url = f"{base_url}{path}"
        
        # Prepare request
        method = endpoint.method  # HttpMethod enum value
        request_headers = headers or {}
        
        auth_method = os.getenv("OBP_AUTHORIZATION_VIA", "none").lower()
        match auth_method:
            case "oauth":
                logger.info("Using OAuth authorization method for OBP API call")
                access_token = get_access_token()
                if not access_token:
                    logger.error("No access token available in context for OAuth authorization.")
                else:
                    # TODO: Elicit a simple approval here to confirm tool use?
                    request_headers["Authorization"] = f"Bearer {access_token}"
            case "consent":
                consent_jwt = (headers or {}).get("Consent-JWT")
                if not consent_jwt:
                    return json.dumps({
                        "error": "consent_required",
                        "endpoint_id": endpoint_id,
                        "operation_id": endpoint.operation_id,
                        "method": endpoint.method,
                        "path": endpoint.path,
                        "required_roles": [role.model_dump() for role in endpoint.roles],
                        "message": f"User consent is required to call {endpoint.operation_id}. "
                                   f"Please approve and provide a Consent-JWT.",
                    }, indent=2)
                request_headers["Consent-JWT"] = consent_jwt
                
                consumer_key = os.getenv("OPEY_OBP_CONSUMER_KEY")
                if consumer_key:
                    request_headers["Consumer-Key"] = consumer_key
                else:
                    logger.warning("OPEY_OBP_CONSUMER_KEY is not set in environment variables. Consent-based authorization will fail without it.")
                    
            case "none":
                # No authorization
                logger.info("No authorization method used for OBP API call")
                pass
            case _:
                logger.error(f"Invalid OBP_AUTHORIZATION_VIA value: {auth_method}")
                return json.dumps({
                    "error": f"Internal server error."
                }, indent=2)
                
        # Make the request
        logger.info(f"Calling OBP API: {method} {url}")
        
        response = requests.request(
            method=method,
            url=url,
            params=query_params,
            json=body,
            headers=request_headers,
            timeout=30
        )
        
        # Return response
        result = {
            "status_code": response.status_code,
            "endpoint_id": endpoint_id,
            "method": method,
            "url": url
        }
        
        try:
            result["response"] = response.json()
            logging.info(f"OBP API call successful: {method} {url} - Status: {response.status_code}")
            logging.info(f"Response: {json.dumps(result['response'], indent=2)[:500]}...")  # Log first 500 chars of response
        except:
            result["response"] = response.text
            logging.info(f"OBP API call with non-JSON response: {method} {url} - Status: {response.status_code}")
            logging.info(f"Response: {result['response'][:500]}...")  # Log first 500 chars of response
        
        return json.dumps(result, indent=2)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
        return json.dumps({
            "error": "API request failed",
            "details": str(e)
        }, indent=2)
    except Exception as e:
        logger.error(f"Error calling OBP API: {e}")
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# GLOSSARY TOOLS (Lightweight Index-Based)
# ============================================================================

@mcp.tool()
def list_glossary_terms(search_query: str = "") -> str:
    """
    List OBP glossary terms. Optionally filter by search query.
    
    Returns a lightweight list of glossary terms with their IDs and titles.
    Use get_glossary_term() to fetch the full definition of a specific term.
    
    Args:
        search_query: Optional search string to filter terms by title or description (case-insensitive)
    
    Returns:
        JSON string with glossary terms including: id, title
    
    Example:
        list_glossary_terms() -> Returns all glossary terms
        list_glossary_terms("oauth") -> Returns OAuth-related terms
    """
    try:
        index = get_glossary_index()
        
        if search_query:
            terms = index.search_terms(search_query)
            message = f"Found {len(terms)} terms matching '{search_query}'"
        else:
            terms = index.list_all_terms()
            message = f"Total glossary terms: {len(terms)}"
        
        # Return lightweight list
        term_list = [
            {"id": term["id"], "title": term["title"]}
            for term in terms
        ]
        
        return json.dumps({
            "message": message,
            "count": len(term_list),
            "terms": term_list[:100]  # Limit to first 100 to avoid token overflow
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error listing glossary terms: {e}")
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def get_glossary_term(term_id: str) -> str:
    """
    Get the full definition of a specific glossary term by ID.
    
    Returns the complete glossary term including title and description (markdown and HTML formats).
    
    Args:
        term_id: The unique identifier of the glossary term (e.g., "account-account-id", "oauth", "api")
    
    Returns:
        JSON string with full term details including title and description
    
    Example:
        get_glossary_term("oauth") -> Full OAuth definition
        get_glossary_term("account-account-id") -> Full Account ID definition
    """
    try:
        index = get_glossary_index()
        term = index.get_term(term_id)
        
        if not term:
            # Try to find similar terms
            all_terms = index.list_all_terms()
            similar = [t for t in all_terms if term_id.lower() in t["id"].lower()][:5]
            
            return json.dumps({
                "error": f"Glossary term '{term_id}' not found",
                "suggestion": "Use list_glossary_terms() to find available terms",
                "similar_terms": [{"id": t["id"], "title": t["title"]} for t in similar] if similar else []
            }, indent=2)
        
        return json.dumps(term, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting glossary term: {e}")
        return json.dumps({"error": str(e)}, indent=2)


# ============================================================================
# GLOSSARY RESOURCES (For MCP Clients That Support Resources)
# ============================================================================

@mcp.resource("obp://glossary")
def glossary_list() -> str:
    """
    Get the complete list of OBP glossary terms.
    
    Returns a formatted list of all available glossary terms with their IDs and titles.
    Each term can be accessed individually via obp://glossary/{term_id}.
    """
    try:
        index = get_glossary_index()
        terms = index.list_all_terms()
        
        # Format as a readable text list
        output = f"# OBP Glossary Terms ({len(terms)} total)\n\n"
        output += "Available glossary terms:\n\n"
        
        for term in terms[:50]:  # Show first 50 terms
            output += f"- **{term['title']}** (id: `{term['id']}`)\n"
        
        if len(terms) > 50:
            output += f"\n... and {len(terms) - 50} more terms.\n"
        
        output += "\nAccess individual terms using: obp://glossary/{term_id}\n"
        
        return output
        
    except Exception as e:
        logger.error(f"Error listing glossary terms: {e}")
        return f"Error: {str(e)}"


@mcp.resource("obp://glossary/{term_id}")
def glossary_term(term_id: str) -> str:
    """
    Get a specific glossary term by ID.
    
    Returns the full glossary term including title and description in markdown format.
    
    Args:
        term_id: The unique identifier of the glossary term (e.g., "account-account-id")
    
    Example URIs:
        - obp://glossary/account-account-id
        - obp://glossary/api
        - obp://glossary/bank-bank-id
    """
    try:
        index = get_glossary_index()
        term = index.get_term(term_id)
        
        if not term:
            # Try to find similar terms
            all_terms = index.list_all_terms()
            similar = [t for t in all_terms if term_id.lower() in t["id"].lower()][:5]
            
            output = f"# Error: Glossary term '{term_id}' not found\n\n"
            output += "Use obp://glossary to list all available terms.\n\n"
            
            if similar:
                output += "Similar terms:\n"
                for t in similar:
                    output += f"- {t['title']} (id: `{t['id']}`)\n"
            
            return output
        
        # Format the term as markdown
        output = f"# {term['title']}\n\n"
        output += f"**ID:** `{term['id']}`\n\n"
        output += "## Description\n\n"
        
        description = term.get('description', {})
        markdown = description.get('markdown', '')
        
        if markdown:
            output += markdown
        else:
            output += "No description available."
        
        return output
        
    except Exception as e:
        logger.error(f"Error getting glossary term: {e}")
        return f"Error: {str(e)}"


# ============================================================================
# HTTP SERVER CONFIGURATION
# ============================================================================

if __name__ == "__main__":
    # Run the FastMCP server with http transport (default)
    # This is used for local MCP clients like Claude Desktop
    mcp.run(
        transport="streamable-http",
        log_level="DEBUG",
        #json_reponse=True,
        stateless_http=True,
        host=os.getenv("FASTMCP_HOST", "127.0.0.1"),
        port=int(os.getenv("FASTMCP_PORT", "9100")),
    )
