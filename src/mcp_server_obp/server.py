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
from src.tools.retrieval import endpoint_retrieval_graph, glossary_retrieval_graph, GlossarySearchInput, GlossarySearchOutput, EndpointSearchInput, EndpointSearchOutput
from utils.formatters import endpoint_formatter, glossary_formatter
from src.tools.endpoint_index import get_endpoint_index

mcp = FastMCP("Open Bank Project", log_level="DEBUG")

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
    
    This validates parameters against the endpoint schema and makes the actual API call.
    Requires OBP_BASE_URL and OBP_API_VERSION environment variables to be set.
    You may also need authentication headers depending on the endpoint.
    
    Args:
        endpoint_id: The unique identifier of the endpoint
        path_params: Dictionary of path parameters (e.g., {"ACCOUNT_ID": "123"})
        query_params: Dictionary of query parameters (e.g., {"limit": 10})
        body: Request body as dictionary (for POST/PUT requests)
        headers: Additional HTTP headers (e.g., {"Authorization": "DirectLogin token=..."})
    
    Returns:
        JSON string with API response or error details
    
    Example:
        call_obp_api("GET-obp-vVERSION-banks", query_params={"limit": 5})
    """
    try:
        index = get_endpoint_index()
        
        # Get endpoint info
        endpoint = index.get_endpoint_by_id(endpoint_id)
        if not endpoint:
            return json.dumps({
                "error": f"Endpoint '{endpoint_id}' not found",
                "suggestion": "Use list_endpoints_by_tag() to find available endpoints"
            }, indent=2)
        
        # Get full schema for validation
        schema = index.get_endpoint_schema(endpoint_id)
        if not schema:
            return json.dumps({
                "error": f"Could not load schema for endpoint '{endpoint_id}'"
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
# DEPRECATED RAG-BASED TOOLS (Legacy)
# ============================================================================
# These tools use RAG (Retrieval Augmented Generation) with vector databases
# and are more expensive in terms of tokens and API calls. They are kept for
# backward compatibility but the new tag-based tools above are recommended.

@mcp.tool()
async def retrieve_endpoints(query: str) -> str | None:
    """
    [DEPRECATED - Use list_endpoints_by_tag() instead]
    
    Retrieve Relevant Open Bank Project API Endpoints based on a query using RAG.
    This tool is deprecated in favor of the more cost-effective tag-based approach.
    Use list_endpoints_by_tag() -> get_endpoint_schema() -> call_obp_api() instead.
    """
    logger.warning("retrieve_endpoints() is deprecated. Use list_endpoints_by_tag() instead.")
    _input = EndpointSearchInput(question=query)
    
    output = await endpoint_retrieval_graph.ainvoke(_input)
    
    formatted_output = endpoint_formatter(output["output_documents"])
    
    return formatted_output

@mcp.tool()
async def retrieve_glossary_terms(query: str) -> str | None:
    """Retrieve Relevant Glossary Terms based on a query."""
    _input = GlossarySearchInput(question=query)
    
    glossary_output = await glossary_retrieval_graph.ainvoke(_input)
    
    formatted_output = glossary_formatter(glossary_output["output_documents"])
    
    return formatted_output
    
    