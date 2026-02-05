import json

from fastmcp import Context
from fastmcp.server.elicitation import (
    AcceptedElicitation,
    DeclinedElicitation,
    CancelledElicitation
)
from dataclasses import dataclass
from typing import Any, List

from src.tools.endpoint_index import get_endpoint_index
from src.tools import EndpointSchema, RoleRequirement

@dataclass
class ApprovalConsent:
    consent_jwt: str


async def elicit_consent(ctx: Context, endpoint: EndpointSchema) -> AcceptedElicitation[ApprovalConsent] | DeclinedElicitation | CancelledElicitation:
    """
    Elicit user consent for accessing a given OBP endpoint.
    """
    
    prompt = f"Endpoint with operation ID '{endpoint.operation_id}' needs your permission to run."
    
    # This message should be json-serializable so we can extract information at the frontend
    message_json = {
        "operation_id": endpoint.operation_id,
        "message_prompt": prompt,
        "required_roles": [role.model_dump() for role in endpoint.roles] # we will use these to construct our narrowly-scoped consent
    }
    
    response = await ctx.elicit(
        message=json.dumps(message_json),
        response_type=ApprovalConsent,
    )
    
    return response
    
    
    