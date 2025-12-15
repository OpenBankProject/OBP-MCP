import sys
import logging
import os
import json
import requests
from pathlib import Path
from typing import List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)

# Add the src and project root directories to the Python path when running as a script
_src_dir = Path(__file__).parent.parent
_project_root = _src_dir.parent
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession
from mcp.server.auth.settings import AuthSettings
from pydantic import AnyUrl

from src.tools.endpoint_index import get_endpoint_index
from src.tools.glossary_index import get_glossary_index

mcp = FastMCP(
    "Open Bank Project",
    stateless_http=True,
    json_response=True,
    log_level="DEBUG",
)

logger = logging.getLogger(__name__)

# ============================================================================
# NEW HYBRID TAG-BASED ENDPOINT TOOLS (RECOMMENDED)
# ============================================================================

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
        
        return json.dumps({
            "count": len(endpoints),
            "endpoints": endpoints
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error listing endpoints by tag: {e}")
        return json.dumps({"error": str(e)}, indent=2)


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
        
        return json.dumps(schema, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting endpoint schema: {e}")
        return json.dumps({"error": str(e)}, indent=2)


@mcp.tool()
def call_obp_api(
    endpoint_id: str,
    path_params: dict = None,
    query_params: dict = None,
    body: dict = None,
    headers: dict = None
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
        endpoint = index.get_endpoint_by_id(endpoint_id)
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
        path = endpoint["path"]
        if path_params:
            for key, value in path_params.items():
                path = path.replace(f"{{{key}}}", str(value))
        
        # Replace VERSION placeholder
        path = path.replace("VERSION", api_version)
        
        # Build full URL
        url = f"{base_url}{path}"
        
        # Prepare request
        method = endpoint["method"].upper()
        request_headers = headers or {}
        
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
        except:
            result["response"] = response.text
        
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
def get_glossary_list() -> str:
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
def get_glossary_term(term_id: str) -> str:
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
    mcp.run(transport="streamable-http")
