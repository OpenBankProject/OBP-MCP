from fastmcp import Context
from dataclasses import dataclass
from typing import Any

from src.tools.endpoint_index import get_endpoint_index

@dataclass
class ApprovalConsent:
    consent_id: str
    
    
def get_roles_for_endpoint(endpoint_id: str) -> list[str]:
    """
    Gets the required entitlements for a given OBP endpoint from its ID.
    """
    
    index = get_endpoint_index()
    endpoint = index.get_endpoint_schema(endpoint_id)
    if not endpoint:
        raise ValueError(f"Endpoint with ID '{endpoint_id}' not found in index.")
    
    return endpoint.roles