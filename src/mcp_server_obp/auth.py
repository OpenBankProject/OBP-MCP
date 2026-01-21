"""Authentication providers for OBP-MCP.

This module provides authentication solutions for integrating with different
OAuth 2.1 / OpenID Connect identity providers:

1. KeycloakAuthProvider - For Keycloak identity servers (with DCR proxy workaround)
2. OBPOIDCAuthProvider - For OBP-OIDC identity servers (native DCR support)

Both providers support Dynamic Client Registration (RFC 7591) for seamless
MCP client authentication.
"""

from __future__ import annotations

import os
import logging
from enum import Enum
from typing import Optional

import httpx
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.server.auth import RemoteAuthProvider, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.utilities.auth import parse_scopes

logger = logging.getLogger(__name__)


class AuthProviderType(str, Enum):
    """Supported authentication provider types."""
    KEYCLOAK = "keycloak"
    OBP_OIDC = "obp-oidc"
    NONE = "none"


class KeycloakAuthProvider(RemoteAuthProvider):
    """Keycloak authentication provider with Dynamic Client Registration (DCR) support.

    This provider integrates FastMCP with Keycloak using a **minimal proxy architecture** that
    solves a specific MCP compatibility issue. The proxy only intercepts DCR responses to fix
    a single field - all other OAuth operations go directly to Keycloak.

    ## Why a Minimal Proxy is Needed (for older Keycloak versions)

    **Note:** Keycloak fixed this issue in PR #45309 (merged January 12, 2026). Once you upgrade
    to a Keycloak version that includes this fix, the proxy workaround will no longer be necessary.

    Older Keycloak versions have a known limitation with Dynamic Client Registration: they ignore
    the client's requested `token_endpoint_auth_method` parameter and always return
    `client_secret_basic`, even when clients explicitly request `client_secret_post` (which MCP
    requires per RFC 9110).

    This minimal proxy works around this by:
    1. Advertising itself as the authorization server to MCP clients
    2. Forwarding Keycloak's OAuth metadata with a custom registration endpoint
    3. Intercepting DCR responses from Keycloak and fixing only the `token_endpoint_auth_method` field

    **What the minimal proxy does NOT intercept:**
    - Authorization flows (users authenticate directly with Keycloak)
    - Token issuance (tokens come directly from Keycloak)
    - Token validation (JWT signatures verified against Keycloak's keys)

    **Reference:** https://github.com/keycloak/keycloak/pull/45309

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_server_obp.auth import KeycloakAuthProvider

        keycloak_auth = KeycloakAuthProvider(
            realm_url="http://localhost:8080/realms/fastmcp",
            base_url="http://localhost:8000",
            required_scopes=["openid", "profile"],
        )

        mcp = FastMCP("My App", auth=keycloak_auth)
        ```
    """

    def __init__(
        self,
        *,
        realm_url: AnyHttpUrl | str,
        base_url: AnyHttpUrl | str,
        required_scopes: list[str] | str | None = None,
        audience: str | list[str] | None = None,
        token_verifier: TokenVerifier | None = None,
    ):
        """Initialize Keycloak metadata provider.

        Args:
            realm_url: Your Keycloak realm URL (e.g., "https://keycloak.example.com/realms/myrealm")
            base_url: Public URL of this FastMCP server
            required_scopes: Optional list of scopes to require for all requests.
            audience: Optional audience(s) for JWT validation.
            token_verifier: Optional token verifier. If None, creates JWT verifier for Keycloak
        """
        if isinstance(base_url, str):
            base_url = AnyHttpUrl(base_url)
        self.base_url = AnyHttpUrl(str(base_url).rstrip("/"))
        self.realm_url = str(realm_url).rstrip("/")

        parsed_scopes = parse_scopes(required_scopes) if required_scopes else None

        if token_verifier is None:
            token_verifier = JWTVerifier(
                jwks_uri=f"{self.realm_url}/protocol/openid-connect/certs",
                issuer=self.realm_url,
                algorithm="RS256",
                required_scopes=parsed_scopes,
                audience=audience,
            )

        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[self.base_url],
            base_url=self.base_url,
        )

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Get OAuth routes including Keycloak metadata forwarding and minimal DCR proxy."""
        routes = super().get_routes(mcp_path)

        async def oauth_authorization_server_metadata(request):
            """Forward Keycloak's OAuth metadata with registration endpoint pointing to our minimal DCR proxy."""
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{self.realm_url}/.well-known/oauth-authorization-server"
                    )
                    response.raise_for_status()
                    metadata = response.json()

                    base_url = str(self.base_url).rstrip("/")
                    metadata["registration_endpoint"] = f"{base_url}/register"

                    return JSONResponse(metadata)
            except Exception as e:
                logger.error(f"Failed to fetch Keycloak metadata: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch Keycloak metadata: {e}"},
                    status_code=500,
                )

        routes.append(
            Route("/.well-known/oauth-authorization-server", endpoint=oauth_authorization_server_metadata, methods=["GET"])
        )

        async def register_client_fix_auth_method(request):
            """Minimal DCR proxy that fixes token_endpoint_auth_method in Keycloak's response."""
            try:
                body = await request.body()

                async with httpx.AsyncClient(timeout=10.0) as client:
                    forward_headers = {
                        key: value
                        for key, value in request.headers.items()
                        if key.lower() not in {"host", "content-length", "transfer-encoding"}
                    }
                    forward_headers["Content-Type"] = "application/json"

                    registration_endpoint = f"{self.realm_url}/clients-registrations/openid-connect"
                    response = await client.post(registration_endpoint, content=body, headers=forward_headers)

                    if response.status_code != 201:
                        return JSONResponse(
                            response.json() if response.headers.get("content-type", "").startswith("application/json") else {"error": "registration_failed"},
                            status_code=response.status_code,
                        )

                    client_info = response.json()
                    original_auth_method = client_info.get("token_endpoint_auth_method")
                    logger.debug(f"Received token_endpoint_auth_method from Keycloak: {original_auth_method}")

                    if original_auth_method == "client_secret_basic":
                        logger.debug("Fixing token_endpoint_auth_method: client_secret_basic -> client_secret_post")
                        client_info["token_endpoint_auth_method"] = "client_secret_post"

                    return JSONResponse(client_info, status_code=201)

            except Exception as e:
                logger.error(f"DCR proxy error: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Client registration failed: {e}"},
                    status_code=500,
                )

        routes.append(Route("/register", endpoint=register_client_fix_auth_method, methods=["POST"]))

        return routes


class OBPOIDCAuthProvider(RemoteAuthProvider):
    """OBP-OIDC authentication provider with native Dynamic Client Registration support.

    This provider integrates FastMCP with OBP-OIDC (Open Bank Project's OIDC server),
    which has native support for Dynamic Client Registration (RFC 7591) and returns
    the correct `token_endpoint_auth_method` value without any proxy workarounds.

    ## Features

    - **Native DCR Support**: OBP-OIDC correctly handles `token_endpoint_auth_method`
    - **No Proxy Required**: All OAuth operations go directly to OBP-OIDC
    - **Standard OIDC Discovery**: Uses standard `.well-known/openid-configuration`
    - **JWT Validation**: Tokens validated against OBP-OIDC's JWKS endpoint

    ## OBP-OIDC Endpoints

    | Endpoint | Path |
    |----------|------|
    | Discovery | `{issuer}/.well-known/openid-configuration` |
    | Authorization | `{issuer}/auth` |
    | Token | `{issuer}/token` |
    | JWKS | `{issuer}/jwks` |
    | UserInfo | `{issuer}/userinfo` |
    | Registration (DCR) | `{issuer}/connect/register` |
    | Revocation | `{issuer}/revoke` |

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_server_obp.auth import OBPOIDCAuthProvider

        obp_auth = OBPOIDCAuthProvider(
            issuer_url="http://localhost:9000/obp-oidc",
            base_url="http://localhost:8000",
            required_scopes=["openid", "profile", "email"],
        )

        mcp = FastMCP("OBP MCP Server", auth=obp_auth)
        ```
    """

    def __init__(
        self,
        *,
        issuer_url: AnyHttpUrl | str,
        base_url: AnyHttpUrl | str,
        required_scopes: list[str] | str | None = None,
        audience: str | list[str] | None = None,
        token_verifier: TokenVerifier | None = None,
    ):
        """Initialize OBP-OIDC authentication provider.

        Args:
            issuer_url: Your OBP-OIDC issuer URL (e.g., "http://localhost:9000/obp-oidc")
            base_url: Public URL of this FastMCP server
            required_scopes: Optional list of scopes to require for all requests.
            audience: Optional audience(s) for JWT validation.
            token_verifier: Optional token verifier. If None, creates JWT verifier for OBP-OIDC
        """
        if isinstance(base_url, str):
            base_url = AnyHttpUrl(base_url)
        self.base_url = AnyHttpUrl(str(base_url).rstrip("/"))
        self.issuer_url = str(issuer_url).rstrip("/")

        parsed_scopes = parse_scopes(required_scopes) if required_scopes else None

        if token_verifier is None:
            # OBP-OIDC uses standard OIDC endpoint patterns
            token_verifier = JWTVerifier(
                jwks_uri=f"{self.issuer_url}/jwks",
                issuer=self.issuer_url,
                algorithm="RS256",
                required_scopes=parsed_scopes,
                audience=audience,
            )

        # OBP-OIDC is advertised directly as the authorization server
        # No proxy needed - OBP-OIDC has native DCR support with correct token_endpoint_auth_method
        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(self.issuer_url)],
            base_url=self.base_url,
        )

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        """Get OAuth routes for OBP-OIDC.
        
        OBP-OIDC has native DCR support, but some MCP clients may still try to fetch
        discovery documents from the resource server (FastMCP) rather than the 
        authorization server (OBP-OIDC). We provide forwarding routes to handle this.
        """
        routes = super().get_routes(mcp_path)

        async def forward_oauth_authorization_server_metadata(request):
            """Forward OAuth authorization server metadata from OBP-OIDC."""
            try:
                async with httpx.AsyncClient() as client:
                    # Try OAuth 2.0 authorization server metadata first
                    response = await client.get(
                        f"{self.issuer_url}/.well-known/oauth-authorization-server"
                    )
                    if response.status_code == 404:
                        # Fall back to OIDC discovery
                        response = await client.get(
                            f"{self.issuer_url}/.well-known/openid-configuration"
                        )
                    response.raise_for_status()
                    metadata = response.json()
                    return JSONResponse(metadata)
            except Exception as e:
                logger.error(f"Failed to fetch OBP-OIDC metadata: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch OBP-OIDC metadata: {e}"},
                    status_code=500,
                )

        async def forward_openid_configuration(request):
            """Forward OIDC discovery document from OBP-OIDC."""
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.get(
                        f"{self.issuer_url}/.well-known/openid-configuration"
                    )
                    response.raise_for_status()
                    metadata = response.json()
                    return JSONResponse(metadata)
            except Exception as e:
                logger.error(f"Failed to fetch OBP-OIDC openid-configuration: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch OBP-OIDC discovery: {e}"},
                    status_code=500,
                )

        async def forward_register(request):
            """Forward Dynamic Client Registration requests to OBP-OIDC."""
            try:
                body = await request.body()

                async with httpx.AsyncClient(timeout=10.0) as client:
                    forward_headers = {
                        key: value
                        for key, value in request.headers.items()
                        if key.lower() not in {"host", "content-length", "transfer-encoding"}
                    }
                    forward_headers["Content-Type"] = "application/json"

                    # OBP-OIDC's DCR endpoint
                    registration_endpoint = f"{self.issuer_url}/connect/register"
                    response = await client.post(registration_endpoint, content=body, headers=forward_headers)

                    # Forward the response as-is (OBP-OIDC returns correct token_endpoint_auth_method)
                    return JSONResponse(
                        response.json() if response.headers.get("content-type", "").startswith("application/json") else {"error": "registration_failed"},
                        status_code=response.status_code,
                    )

            except Exception as e:
                logger.error(f"DCR forward error: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Client registration failed: {e}"},
                    status_code=500,
                )

        # Add forwarding routes for clients that fetch from the resource server
        routes.append(
            Route("/.well-known/oauth-authorization-server", endpoint=forward_oauth_authorization_server_metadata, methods=["GET"])
        )
        routes.append(
            Route("/.well-known/openid-configuration", endpoint=forward_openid_configuration, methods=["GET"])
        )
        routes.append(
            Route("/register", endpoint=forward_register, methods=["POST"])
        )

        return routes


def get_auth_provider(
    provider_type: AuthProviderType | str | None = None,
    base_url: str | None = None,
    required_scopes: list[str] | None = None,
    # Keycloak-specific
    keycloak_realm_url: str | None = None,
    # OBP-OIDC-specific
    obp_oidc_issuer_url: str | None = None,
    audience: str | list[str] | None = None,
) -> RemoteAuthProvider | None:
    """Factory function to create the appropriate authentication provider.

    This function reads configuration from environment variables if not explicitly provided.

    Environment Variables:
        - ENABLE_OAUTH: Set to "true" to enable OAuth (default: "false")
        - AUTH_PROVIDER: Provider type - "keycloak" or "obp-oidc" (default: "keycloak")
        - BASE_URL: Public URL of the FastMCP server
        - KEYCLOAK_REALM_URL: Keycloak realm URL (for Keycloak provider)
        - OBP_OIDC_ISSUER_URL: OBP-OIDC issuer URL (for OBP-OIDC provider)

    Args:
        provider_type: The type of auth provider to use
        base_url: Public URL of this FastMCP server
        required_scopes: Scopes to require for all requests
        keycloak_realm_url: Keycloak realm URL (for Keycloak provider)
        obp_oidc_issuer_url: OBP-OIDC issuer URL (for OBP-OIDC provider)
        audience: Audience(s) for JWT validation

    Returns:
        An authentication provider instance, or None if OAuth is disabled

    Example:
        ```python
        # Using environment variables
        auth = get_auth_provider()

        # Explicit configuration
        auth = get_auth_provider(
            provider_type=AuthProviderType.OBP_OIDC,
            base_url="http://localhost:8000",
            obp_oidc_issuer_url="http://localhost:9000/obp-oidc",
            required_scopes=["openid", "profile"],
        )

        mcp = FastMCP("My Server", auth=auth)
        ```
    """
    # Check if OAuth is enabled
    enable_oauth = os.getenv("ENABLE_OAUTH", "false").lower() == "true"
    if not enable_oauth:
        logger.info("OAuth is disabled; running in unauthenticated mode.")
        return None

    logger.info("OAuth is enabled; setting up authentication.")

    # Determine provider type
    if provider_type is None:
        provider_type = os.getenv("AUTH_PROVIDER", "keycloak").lower()
    
    if isinstance(provider_type, str):
        try:
            provider_type = AuthProviderType(provider_type)
        except ValueError:
            raise ValueError(f"Unknown auth provider type: {provider_type}. Valid options: {[e.value for e in AuthProviderType]}")

    if provider_type == AuthProviderType.NONE:
        logger.info("Auth provider set to 'none'; running in unauthenticated mode.")
        return None

    # Get base URL
    base_url = base_url or os.getenv("BASE_URL")
    if not base_url:
        raise ValueError("BASE_URL must be set when OAuth is enabled.")

    # Default scopes if not provided
    if required_scopes is None:
        required_scopes = ["openid", "profile", "email"]

    # Create the appropriate provider
    if provider_type == AuthProviderType.KEYCLOAK:
        keycloak_realm_url = keycloak_realm_url or os.getenv("KEYCLOAK_REALM_URL")
        if not keycloak_realm_url:
            raise ValueError("KEYCLOAK_REALM_URL must be set when using Keycloak provider.")
        
        logger.info(f"Configuring Keycloak auth provider with realm: {keycloak_realm_url}")
        return KeycloakAuthProvider(
            realm_url=AnyHttpUrl(keycloak_realm_url),
            base_url=AnyHttpUrl(base_url),
            required_scopes=required_scopes,
            audience=audience,
        )

    elif provider_type == AuthProviderType.OBP_OIDC:
        obp_oidc_issuer_url = obp_oidc_issuer_url or os.getenv("OBP_OIDC_ISSUER_URL")
        if not obp_oidc_issuer_url:
            raise ValueError("OBP_OIDC_ISSUER_URL must be set when using OBP-OIDC provider.")
        
        logger.info(f"Configuring OBP-OIDC auth provider with issuer: {obp_oidc_issuer_url}")
        return OBPOIDCAuthProvider(
            issuer_url=AnyHttpUrl(obp_oidc_issuer_url),
            base_url=AnyHttpUrl(base_url),
            required_scopes=required_scopes,
            audience=audience,
        )

    else:
        raise ValueError(f"Unknown auth provider type: {provider_type}")


# Convenience exports
__all__ = [
    "AuthProviderType",
    "KeycloakAuthProvider",
    "OBPOIDCAuthProvider",
    "get_auth_provider",
]
