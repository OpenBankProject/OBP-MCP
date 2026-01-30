"""
Utility functions for OBP API data fetching.
"""
import os
import requests
from typing import Dict, Any


def get_obp_config(endpoint_type="static"):
    """Get OBP configuration from environment variables."""
    base_url = os.getenv("OBP_BASE_URL")
    api_version = os.getenv("OBP_API_VERSION")
    
    if not all([base_url, api_version]):
        raise ValueError("Missing required environment variables: OBP_BASE_URL, OBP_API_VERSION")
    
    return {
        "base_url": base_url,
        "api_version": api_version,
        "glossary_url": f"{base_url}/obp/{api_version}/api/glossary",
        "swagger_url": f"{base_url}/obp/{api_version}/resource-docs/{api_version}/swagger?content={endpoint_type}"
    }


def fetch_obp_data(url: str) -> Dict[str, Any]:
    """Fetch data from OBP API endpoint."""
    print(f"Fetching data from: {url}")
    response = requests.get(url, timeout=30)
    try:
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        print(f"HTTP error from {url}: {e}")
        print(f"OBP response body: {response.text}")
        raise
    return response.json()
