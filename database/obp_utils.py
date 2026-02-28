"""
Utility functions for OBP API data fetching.
"""
import os
import requests
from typing import Dict, Any


def get_obp_config(endpoint_type: str = "static", use_resource_docs: bool = True) -> Dict[str, str]:
    """
    Get OBP configuration from environment variables.
    
    Args:
        endpoint_type: Type of endpoints to fetch ("static", "dynamic", or "all")
        use_resource_docs: If True, use resource-docs endpoint (includes roles).
                          If False, use swagger endpoint.
    
    Returns:
        Dictionary with configuration including URLs for data fetching
    """
    base_url = os.getenv("OBP_BASE_URL")
    api_version = os.getenv("OBP_API_VERSION")
    
    if not all([base_url, api_version]):
        raise ValueError("Missing required environment variables: OBP_BASE_URL, OBP_API_VERSION")
    
    config = {
        "base_url": base_url,
        "api_version": api_version,
        "glossary_url": f"{base_url}/obp/{api_version}/api/glossary",
        "swagger_url": f"{base_url}/obp/{api_version}/resource-docs/{api_version}/swagger?content={endpoint_type}",
        "resource_docs_url": f"{base_url}/obp/{api_version}/resource-docs/{api_version}/obp?content={endpoint_type}",
    }
    
    # Set the primary data URL based on preference
    if use_resource_docs:
        config["data_url"] = config["resource_docs_url"]
        config["data_format"] = "resource_docs"
    else:
        config["data_url"] = config["swagger_url"]
        config["data_format"] = "swagger"
    
    return config


def fetch_obp_data(url: str) -> Dict[str, Any]:
    """Fetch data from OBP API endpoint."""
    print(f"Fetching data from: {url}")
    response = requests.get(url, timeout=60)  # Increased timeout for large responses
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error from {url}: {e}")
        print(f"OBP response body: {response.text}")
        raise
    return response.json()
