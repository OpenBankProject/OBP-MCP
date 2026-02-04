from fastmcp import Context
from dataclasses import dataclass
from typing import Any

from src.tools.endpoint_index import get_endpoint_index

@dataclass
class ApprovalConsent:
    consent_id: str
    
    
def get_required_entitlements(endpoint: dict[str, Any]) -> list[str]:
    """
    Gets the required entitlements for a given OBP endpoint.
    """
    
    