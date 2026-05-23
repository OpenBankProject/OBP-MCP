"""
Utility functions for OBP API data fetching.
"""
import os
import requests
from typing import Dict, Any

DEFAULT_API_VERSION = "v7.0.0"


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
    # Two distinct version axes: the version of the meta-endpoint we hit, and
    # the requestedApiVersion that selects which endpoint catalog comes back.
    version_to_call = os.getenv("OBP_VERSION_TO_CALL", DEFAULT_API_VERSION)
    version_of_interest = os.getenv("API_VERSION_OF_INTEREST", DEFAULT_API_VERSION)

    if not base_url:
        raise ValueError("Missing required environment variable: OBP_BASE_URL")

    config = {
        "base_url": base_url,
        "version_to_call": version_to_call,
        "version_of_interest": version_of_interest,
        "glossary_url": f"{base_url}/obp/{version_to_call}/api/glossary",
        "swagger_url": f"{base_url}/obp/{version_to_call}/resource-docs/{version_of_interest}/swagger?content={endpoint_type}",
        "resource_docs_url": f"{base_url}/obp/{version_to_call}/resource-docs/{version_of_interest}/obp?content={endpoint_type}",
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
