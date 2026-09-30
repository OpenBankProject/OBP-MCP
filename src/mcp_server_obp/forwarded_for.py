"""
This module passes the end user's address on to OBP-API in the X-Forwarded-For header.

The problem it solves: OBP-API applies per-address rate limits, address penalties and its
busiest-callers view to the address of whoever called it. Behind this server, that would
always be this server's address. So every hop between the end user and OBP-API (NGINX,
API Explorer II, Opey, this server) appends to X-Forwarded-For the address of whoever it
received the request from, its TCP peer, and OBP-API works out the end user from the chain.

Why appending is safe: OBP-API reads the chain from the right. It starts with its own TCP
peer, skips every address it lists in its trust.proxy.peers prop, and takes the first
address it does not trust as the client. Anyone can write anything at the left of the
chain, but a caller that OBP-API does not trust becomes the client itself before the walk
ever reaches what that caller wrote. So OBP-API's trust.proxy.peers must list this
server's address, and the address of every hop in front of it.

What this server contributes to the chain, in order, after the chain the MCP client put
in the tool call's headers:
  1. the X-Forwarded-For header of the MCP HTTP request itself, which a proxy in front of
     this server (if any) will have appended the MCP client's address to, and
  2. the TCP peer of the MCP HTTP request.
When there is no HTTP request (stdio transport), nothing vouches for the caller's chain,
so no X-Forwarded-For is sent at all.

The TCP peer must be the real socket peer. Uvicorn rewrites the client address from
X-Forwarded-For by default when the peer is 127.0.0.1, so the server is started with
proxy_headers turned off (see server.py).
"""

import ipaddress
from typing import Mapping, Optional

FORWARDED_FOR_HEADER = "X-Forwarded-For"

# Headers a caller could use to name a client address. They are removed from whatever the
# caller supplied, and X-Forwarded-For is rebuilt from what this server can vouch for.
CLIENT_ADDRESS_HEADERS = {"x-forwarded-for", "x-real-ip", "forwarded"}


def canonical_address(address: str) -> str:
    """Return an address in the form every hop in the chain agrees on.

    IPv6 addresses lose their brackets and are compressed; an IPv4 address that arrived
    in IPv6-mapped form (::ffff:203.0.113.7) is returned as plain IPv4. Anything that is
    not a literal address is returned trimmed but otherwise unchanged.
    """
    unbracketed = address.strip().removeprefix("[").removesuffix("]")
    try:
        parsed = ipaddress.ip_address(unbracketed)
    except ValueError:
        return unbracketed
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def split_chain(header_value: Optional[str]) -> list[str]:
    """Split an X-Forwarded-For value into its addresses, left to right, dropping blanks."""
    if not header_value:
        return []
    return [canonical_address(part) for part in header_value.split(",") if part.strip()]


def find_header(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Return the value of a header, matching its name without regard to case."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def without_client_address_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a copy of the headers with every header that names a client address removed."""
    return {key: value for key, value in headers.items() if key.lower() not in CLIENT_ADDRESS_HEADERS}


def outgoing_forwarded_for(
    caller_chain: Optional[str],
    request_chain: Optional[str],
    tcp_peer: Optional[str],
) -> Optional[str]:
    """Build the X-Forwarded-For value to send to OBP-API.

    caller_chain is the X-Forwarded-For the MCP client put in the tool call's headers,
    request_chain is the X-Forwarded-For header on the MCP HTTP request, and tcp_peer is
    the socket address that request came from. Returns None when there is no TCP peer,
    because then nothing vouches for either chain.
    """
    if not tcp_peer:
        return None
    addresses = split_chain(caller_chain) + split_chain(request_chain) + [canonical_address(tcp_peer)]
    return ", ".join(addresses)


def http_request_addresses() -> tuple[Optional[str], Optional[str]]:
    """Return the X-Forwarded-For header and the TCP peer of the current MCP HTTP request.

    Both are None when the tool is not running inside an HTTP request, for example over
    the stdio transport.
    """
    from fastmcp.server.dependencies import get_http_request

    try:
        request = get_http_request()
    except RuntimeError:
        return None, None
    tcp_peer = request.client.host if request.client else None
    return request.headers.get(FORWARDED_FOR_HEADER), tcp_peer


def headers_for_obp(caller_headers: Optional[Mapping[str, str]]) -> dict[str, str]:
    """Return the headers to send to OBP-API, built from the tool call's headers.

    The result is a new dictionary, so the caller's dictionary is never changed. Any
    client address header the caller supplied is removed, and X-Forwarded-For is set to
    the caller's chain followed by the addresses this server saw itself.
    """
    caller_headers = caller_headers or {}
    outgoing = without_client_address_headers(caller_headers)
    request_chain, tcp_peer = http_request_addresses()
    forwarded_for = outgoing_forwarded_for(
        find_header(caller_headers, FORWARDED_FOR_HEADER), request_chain, tcp_peer
    )
    if forwarded_for:
        outgoing[FORWARDED_FOR_HEADER] = forwarded_for
    return outgoing
