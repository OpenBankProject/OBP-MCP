"""Which of the User's own resources an OBP call needs: the consent's `my_resources` block.

An OBP consent carries three kinds of thing: `views` (the User's own account access),
`entitlements` (Roles the User holds) and `my_resources` (the User's own personal
resources, owned rather than granted). A call to a personal ("my") dynamic entity
endpoint needs the consent to list that entity with the needed action; no Role is
involved. This module works that out from the endpoint path so the consent_required
payload can tell the frontend exactly what to put in the consent.
"""

import re
from typing import Any, Optional

ACTION_READ = "read"
ACTION_WRITE = "write"

# The bank_id OBP uses for the system space: a dynamic entity whose URL has no banks/BANK_ID segment.
SYSTEM_SPACE_BANK_ID = "SYS"

# /obp/dynamic-entity/my/ENTITY[/ID]  or  /obp/dynamic-entity/banks/BANK_ID/my/ENTITY[/ID]
_PERSONAL_DYNAMIC_ENTITY = re.compile(r"^/obp/dynamic-entity/(banks/[^/]+/)?my/([^/]+)")


def my_resources_for(path: Optional[str], method: Optional[str], bank_id: Optional[str]) -> Optional[dict[str, Any]]:
    """Return the `my_resources` block a consent needs for this call, or None if it needs none.

    Only personal dynamic entity endpoints need one today. GET needs `read`; every other
    method needs `write`. `bank_id` is used only for bank-level entities (a `banks/BANK_ID`
    segment in the path); system-level entities carry the system space's bank_id, SYS.
    """
    match = _PERSONAL_DYNAMIC_ENTITY.match(path or "")
    if not match:
        return None
    verb = str(getattr(method, "value", method) or "").upper()
    action = ACTION_READ if verb == "GET" else ACTION_WRITE
    if match.group(1) and not bank_id:
        # A bank-level entity with no bank named. OBP reads an empty bank_id as the system space,
        # so sending one would ask for the system entity of the same name; ask for nothing instead.
        return None
    entity_bank_id = bank_id if match.group(1) else SYSTEM_SPACE_BANK_ID
    return {
        "personal_dynamic_entities": [
            {"bank_id": entity_bank_id, "entity_name": match.group(2), "actions": [action]}
        ]
    }
