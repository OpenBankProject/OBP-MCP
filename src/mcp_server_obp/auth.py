"""Authentication providers for OBP-MCP.

This module provides authentication solutions for integrating with different
OAuth 2.1 / OpenID Connect identity providers:

1. KeycloakAuthProvider - For Keycloak identity servers (with DCR proxy workaround)
2. OBPOIDCAuthProvider - For OBP-OIDC identity servers (native DCR support)
3. create_bearer_auth() - For simple JWT token validation (no OAuth flow)
4. MultiIssuerJWTVerifier - For validating tokens from multiple IdPs simultaneously

The first two providers support Dynamic Client Registration (RFC 7591) for seamless
MCP client authentication via the full OAuth flow.

The third and fourth options are for architectures where OAuth is handled externally
(e.g., by a frontend application) and the MCP server only needs to validate tokens.
"""

from __future__ import annotations

import os
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

import httpx
import jwt as pyjwt  # PyJWT library for decoding without verification
from pydantic import AnyHttpUrl
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.server.auth import RemoteAuthProvider, TokenVerifier
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.utilities.auth import parse_scopes

logger = logging.getLogger(__name__)


async def _log_token_diagnostics(
    token: str,
    *,
    expected_issuer: str | list[str] | None,
    expected_audience: str | list[str] | None,
    expected_algorithm: str | None,
    jwks_uri: str | None,
    required_scopes: list[str] | set[str] | None = None,
    exception: Exception | None = None,
) -> None:
    """Decode a failing JWT without verification and log everything relevant
    for diagnosing why validation failed.

    Logs the token's header (kid, alg) and payload (iss, aud, sub, exp, scope),
    compares them against the verifier's expectations, and fetches the JWKS to
    show which key IDs are currently published.

    This NEVER logs the token itself or its signature — only decoded claims.
    """
    import time

    logger.warning("═══ JWT validation failed — diagnostics ═══")
    if exception is not None:
        logger.warning(f"Verifier raised: {type(exception).__name__}: {exception}")

    # Header (kid, alg, typ)
    token_kid: str | None = None
    token_alg: str | None = None
    try:
        header = pyjwt.get_unverified_header(token)
        token_kid = header.get("kid")
        token_alg = header.get("alg")
        logger.warning(
            f"  Token header: kid={token_kid!r}, alg={token_alg!r}, typ={header.get('typ')!r}"
        )
    except Exception as e:
        logger.warning(f"  Token header: <could not decode: {e}>")

    # Payload (iss, aud, sub, exp, scope, etc.)
    payload: dict = {}
    try:
        payload = pyjwt.decode(token, options={"verify_signature": False})
        exp = payload.get("exp")
        iat = payload.get("iat")
        now = int(time.time())
        expired = (exp is not None and exp < now)
        logger.warning(
            f"  Token payload: iss={payload.get('iss')!r}, aud={payload.get('aud')!r}, "
            f"sub={payload.get('sub')!r}, azp={payload.get('azp')!r}, "
            f"client_id={payload.get('client_id')!r}"
        )
        logger.warning(
            f"  Token timing : iat={iat}, exp={exp}, now={now}, "
            f"expired={expired}, age_s={(now - iat) if iat else 'n/a'}"
        )
        logger.warning(f"  Token scope  : {payload.get('scope')!r} (scp={payload.get('scp')!r})")
    except Exception as e:
        logger.warning(f"  Token payload: <could not decode: {e}>")

    # Expectations
    logger.warning(
        f"  Expected     : issuer={expected_issuer!r}, audience={expected_audience!r}, "
        f"algorithm={expected_algorithm!r}, required_scopes={list(required_scopes) if required_scopes else None}"
    )

    # Specific mismatch checks
    token_iss = payload.get("iss") if payload else None
    token_aud = payload.get("aud") if payload else None

    if expected_issuer and token_iss is not None:
        expected_list = expected_issuer if isinstance(expected_issuer, list) else [expected_issuer]
        if token_iss not in expected_list:
            logger.warning(
                f"  ✗ ISSUER MISMATCH: token iss={token_iss!r} not in expected {expected_list!r}"
            )

    if expected_audience and token_aud is not None:
        token_aud_list = token_aud if isinstance(token_aud, list) else [token_aud]
        expected_aud_list = (
            expected_audience if isinstance(expected_audience, list) else [expected_audience]
        )
        if not any(e in token_aud_list for e in expected_aud_list):
            logger.warning(
                f"  ✗ AUDIENCE MISMATCH: token aud={token_aud!r} does not include any of {expected_aud_list!r}"
            )

    if expected_algorithm and token_alg and token_alg != expected_algorithm:
        logger.warning(
            f"  ✗ ALGORITHM MISMATCH: token alg={token_alg!r}, verifier configured for {expected_algorithm!r}"
        )

    # Fetch JWKS and check whether the token's kid is present
    if jwks_uri and token_kid:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(jwks_uri)
                resp.raise_for_status()
                jwks = resp.json()
            available_kids = [k.get("kid") for k in jwks.get("keys", [])]
            logger.warning(f"  JWKS {jwks_uri} currently publishes kids: {available_kids}")
            if token_kid not in available_kids:
                logger.warning(
                    f"  ✗ KID MISMATCH: token kid={token_kid!r} not in JWKS "
                    f"(likely key rotation or token signed by a different IdP)"
                )
        except Exception as e:
            logger.warning(f"  Could not fetch JWKS for diagnostic comparison: {e}")

    logger.warning("═══ end diagnostics ═══")


class LoggingJWTVerifier(JWTVerifier):
    """Thin subclass of the library's JWTVerifier that logs a full diagnostic
    report whenever token validation fails.

    The base class logs failures only at DEBUG and swallows the reason, which
    makes 401s opaque in production (where LOG_LEVEL is typically INFO). This
    wrapper emits a WARNING with the token's iss/aud/kid/exp/scope, the
    verifier's expectations, and the JWKS keys actually published — enough to
    tell at a glance whether you're looking at key rotation, an issuer
    mismatch, an audience mismatch, or an expired token.
    """

    async def verify_token(self, token: str):
        try:
            result = await super().verify_token(token)
        except Exception as e:
            await _log_token_diagnostics(
                token,
                expected_issuer=self.issuer,
                expected_audience=self.audience,
                expected_algorithm=self.algorithm,
                jwks_uri=self.jwks_uri,
                required_scopes=self.required_scopes,
                exception=e,
            )
            raise
        if result is None:
            await _log_token_diagnostics(
                token,
                expected_issuer=self.issuer,
                expected_audience=self.audience,
                expected_algorithm=self.algorithm,
                jwks_uri=self.jwks_uri,
                required_scopes=self.required_scopes,
            )
        return result


class AuthProviderType(str, Enum):
    """Supported authentication provider types."""
    KEYCLOAK = "keycloak"
    OBP_OIDC = "obp-oidc"
    BEARER_ONLY = "bearer-only"
    NONE = "none"


@dataclass
class IssuerConfig:
    """Configuration for a single JWT issuer."""
    issuer: str
    jwks_uri: str
    algorithm: str = "RS256"
    audience: str | list[str] | None = None


class MultiIssuerJWTVerifier(TokenVerifier):
    """JWT token verifier supporting multiple identity providers.

    This verifier accepts tokens from any of the configured issuers, routing
    token validation to the appropriate JWKS endpoint based on the token's
    `iss` claim.

    This is useful for OBP instances that support multiple OAuth providers
    (e.g., both Keycloak and OBP-OIDC) and need to accept tokens from any
    of them.

    ## How it works

    1. Decodes the incoming token WITHOUT signature verification to extract the `iss` claim
    2. Looks up the issuer in the configured issuers map
    3. Validates the token against that issuer's JWKS endpoint
    4. Falls back to trying all verifiers if the issuer is not recognized

    ## Architecture

    ```
    Token arrives with iss="http://keycloak/realms/foo"
                │
                ▼
    ┌───────────────────────────────────────┐
    │     MultiIssuerJWTVerifier            │
    │  ┌─────────────────────────────────┐  │
    │  │ Peek at `iss` claim (no verify) │  │
    │  └──────────────┬──────────────────┘  │
    │                 │                      │
    │    ┌────────────┴────────────┐        │
    │    ▼                         ▼        │
    │ ┌─────────────┐    ┌─────────────┐    │
    │ │  Keycloak   │    │  OBP-OIDC   │    │
    │ │ JWTVerifier │    │ JWTVerifier │    │
    │ └─────────────┘    └─────────────┘    │
    └───────────────────────────────────────┘
    ```

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_server_obp.auth import MultiIssuerJWTVerifier, IssuerConfig

        auth = MultiIssuerJWTVerifier(
            issuers=[
                IssuerConfig(
                    issuer="http://localhost:8080/realms/fastmcp",
                    jwks_uri="http://localhost:8080/realms/fastmcp/protocol/openid-connect/certs",
                ),
                IssuerConfig(
                    issuer="http://localhost:9000/obp-oidc",
                    jwks_uri="http://localhost:9000/obp-oidc/jwks",
                ),
            ],
            required_scopes=["openid", "profile"],
        )

        mcp = FastMCP("OBP MCP Server", auth=auth)
        ```
    """

    def __init__(
        self,
        *,
        issuers: list[IssuerConfig],
        required_scopes: list[str] | str | None = None,
    ):
        """Initialize multi-issuer JWT verifier.

        Args:
            issuers: List of issuer configurations. Each defines an issuer URL,
                    JWKS endpoint, and optional algorithm/audience settings.
            required_scopes: Optional scopes to require in all tokens.
        """
        if not issuers:
            raise ValueError("At least one issuer must be configured")

        # TokenVerifier doesn't have base_url, but FastMCP's HTTP server expects it
        # Set to None since we're doing bearer-only validation
        self.base_url = None
        
        self.required_scopes = parse_scopes(required_scopes) if required_scopes else None
        self._verifiers: dict[str, JWTVerifier] = {}

        for config in issuers:
            verifier = LoggingJWTVerifier(
                jwks_uri=config.jwks_uri,
                issuer=config.issuer,
                algorithm=config.algorithm,
                required_scopes=self.required_scopes,
                audience=config.audience,
            )
            self._verifiers[config.issuer] = verifier
            logger.debug(f"Registered JWT verifier for issuer: {config.issuer}")

        logger.info(f"MultiIssuerJWTVerifier configured with {len(self._verifiers)} issuers")

    def _extract_issuer(self, token: str) -> str | None:
        """Extract the `iss` claim from a JWT without verifying the signature.

        This is safe because we only use it to route to the correct verifier,
        which then performs full verification.
        """
        try:
            # Decode without verification - we just need the issuer claim
            unverified = pyjwt.decode(token, options={"verify_signature": False})
            issuer = unverified.get("iss")
            logger.debug(f"Extracted issuer from token: {issuer}")
            logger.debug(f"Token claims: sub={unverified.get('sub')}, aud={unverified.get('aud')}, exp={unverified.get('exp')}")
            return issuer
        except pyjwt.exceptions.DecodeError as e:
            logger.warning(f"Failed to decode token to extract issuer: {e}")
            return None

    async def verify_token(self, token: str):
        """Verify a bearer token against the appropriate issuer.

        Args:
            token: The JWT token string to validate

        Returns:
            AccessToken object if valid, None if invalid or expired
        """
        logger.info("🔐 Starting token verification")
        logger.info(f"Token (first 20 chars): {token[:20]}...")
        logger.info(f"Configured issuers: {list(self._verifiers.keys())}")

        # Fast-fail on clearly malformed tokens to avoid noisy verifier errors
        token = token.strip()
        if token.count(".") < 2:
            logger.warning("Rejected token without JWT structure (expected header.payload.signature)")
            return None
        
        # Extract issuer from token
        issuer = self._extract_issuer(token)

        if issuer and issuer in self._verifiers:
            # We know the issuer - use the corresponding verifier
            logger.info(f"✓ Token issuer '{issuer}' matches configured issuer")
            try:
                result = await self._verifiers[issuer].verify_token(token)
                if result:
                    logger.info(f"✓ Token validated successfully by {issuer}")
                    logger.debug(f"Validated token: {result}")
                else:
                    logger.warning(f"✗ Token rejected by {issuer}")
                return result
            except Exception as e:
                logger.error(f"✗ Error validating token with {issuer}: {e}", exc_info=True)
                raise

        # Unknown or missing issuer - try all verifiers in order
        logger.warning(f"⚠ Token issuer '{issuer}' not in configured issuers {list(self._verifiers.keys())}")
        logger.info("Trying all configured verifiers...")
        
        for verifier_issuer, verifier in self._verifiers.items():
            logger.debug(f"Attempting verification with {verifier_issuer}...")
            try:
                result = await verifier.verify_token(token)
                if result is not None:
                    logger.info(f"✓ Token validated successfully by {verifier_issuer} (fallback)")
                    logger.debug(f"Validated token: {result}")
                    return result
                else:
                    logger.debug(f"✗ Token rejected by {verifier_issuer}")
            except Exception as e:
                logger.debug(f"✗ Verifier for {verifier_issuer} rejected token: {e}")
                continue

        logger.error("✗ Token validation failed against all configured issuers")
        return None


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
            token_verifier = LoggingJWTVerifier(
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
            except httpx.HTTPStatusError as e:
                logger.error(f"Failed to fetch Keycloak metadata: {e}")
                logger.error(f"Keycloak response body: {e.response.text}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch Keycloak metadata: {e}"},
                    status_code=500,
                )
            except Exception as e:
                logger.error(f"Failed to fetch Keycloak metadata: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch Keycloak metadata: {e}"},
                    status_code=500,
                )

        suffix = mcp_path or ""
        routes.append(
            Route(f"/.well-known/oauth-authorization-server{suffix}", endpoint=oauth_authorization_server_metadata, methods=["GET"])
        )
        if suffix:
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
            token_verifier = LoggingJWTVerifier(
                jwks_uri=f"{self.issuer_url}/jwks",
                issuer=self.issuer_url,
                algorithm="RS256",
                required_scopes=parsed_scopes,
                audience=audience,
            )

        # Advertise ourselves as the authorization server so all discovery and DCR
        # flows route through our proxy — this lets us fix incompatibilities in
        # OBP-OIDC's responses (e.g. null fields in DCR) before they reach clients.
        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[self.base_url],
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

                    # Route DCR through our proxy so we can fix null fields
                    base_url = str(self.base_url).rstrip("/")
                    metadata["registration_endpoint"] = f"{base_url}/register"

                    return JSONResponse(metadata)
            except httpx.HTTPStatusError as e:
                logger.error(f"Failed to fetch OBP-OIDC metadata: {e}")
                logger.error(f"OBP-OIDC response body: {e.response.text}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch OBP-OIDC metadata: {e}"},
                    status_code=500,
                )
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

                    # Route DCR through our proxy so we can fix null fields
                    base_url = str(self.base_url).rstrip("/")
                    metadata["registration_endpoint"] = f"{base_url}/register"

                    return JSONResponse(metadata)
            except httpx.HTTPStatusError as e:
                logger.error(f"Failed to fetch OBP-OIDC openid-configuration: {e}")
                logger.error(f"OBP-OIDC response body: {e.response.text}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Failed to fetch OBP-OIDC discovery: {e}"},
                    status_code=500,
                )
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

                    if not response.headers.get("content-type", "").startswith("application/json"):
                        return JSONResponse({"error": "registration_failed"}, status_code=response.status_code)

                    client_info = response.json()

                    # Strip null values — OBP-OIDC returns nulls for optional fields
                    # (client_uri, logo_uri, contacts) that strict clients expect to be
                    # absent rather than null
                    client_info = {k: v for k, v in client_info.items() if v is not None}

                    return JSONResponse(client_info, status_code=response.status_code)

            except Exception as e:
                logger.error(f"DCR forward error: {e}")
                return JSONResponse(
                    {"error": "server_error", "error_description": f"Client registration failed: {e}"},
                    status_code=500,
                )

        # Add forwarding routes at both paths:
        # - With mcp_path suffix: for RFC 8414 path-aware discovery from MCP endpoint URL
        # - Without suffix: for OASM discovery from authorization_servers URL (no path)
        suffix = mcp_path or ""
        routes.append(
            Route(f"/.well-known/oauth-authorization-server{suffix}", endpoint=forward_oauth_authorization_server_metadata, methods=["GET"])
        )
        routes.append(
            Route(f"/.well-known/openid-configuration{suffix}", endpoint=forward_openid_configuration, methods=["GET"])
        )
        if suffix:
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


def create_bearer_auth(
    *,
    jwks_uri: str,
    issuer: str,
    required_scopes: list[str] | str | None = None,
    audience: str | list[str] | None = None,
    algorithm: str = "RS256",
) -> JWTVerifier:
    """Create a simple JWT token verifier for bearer-only authentication.

    This is the recommended approach for architectures where:
    - The OAuth flow is handled by a frontend application (browser)
    - The frontend passes the access token to a backend API
    - The backend forwards the token to the MCP server
    - The MCP server only validates tokens - it does NOT initiate OAuth flows

    Unlike the full OAuth providers (KeycloakAuthProvider, OBPOIDCAuthProvider),
    this does NOT expose any OAuth endpoints. It simply validates incoming
    Bearer tokens against the IdP's JWKS endpoint.

    ## Architecture

    ```
    ┌──────────────┐     OAuth Flow      ┌──────────────┐
    │   Browser    │────────────────────▶│  OBP-OIDC    │
    │  (Frontend)  │◀────────────────────│  (IdP)       │
    └──────┬───────┘    access_token     └──────┬───────┘
           │                                    │
           │ HTTP Request                       │
           │ Authorization: Bearer <token>      │
           ▼                                    │
    ┌──────────────┐                            │
    │  Your Agent  │                            │
    │  (Backend)   │                            │
    └──────┬───────┘                            │
           │                                    │
           │ MCP Protocol                       │
           │ Authorization: Bearer <token>      │
           ▼                                    │
    ┌──────────────┐    Validate via JWKS       │
    │  OBP-MCP     │────────────────────────────┘
    │  Server      │
    └──────────────┘
    ```

    Args:
        jwks_uri: URL to the JWKS endpoint for token validation
                  (e.g., "http://localhost:9000/obp-oidc/jwks")
        issuer: Expected issuer claim in the JWT
                (e.g., "http://localhost:9000/obp-oidc")
        required_scopes: Optional scopes to require in the token
        audience: Optional audience(s) to validate in the token
        algorithm: JWT signing algorithm (default: RS256)

    Returns:
        JWTVerifier instance that can be passed directly to FastMCP's auth parameter

    Example:
        ```python
        from fastmcp import FastMCP
        from mcp_server_obp.auth import create_bearer_auth

        auth = create_bearer_auth(
            jwks_uri="http://localhost:9000/obp-oidc/jwks",
            issuer="http://localhost:9000/obp-oidc",
            required_scopes=["openid", "profile"],
        )

        mcp = FastMCP("OBP MCP Server", auth=auth)
        ```
    """
    parsed_scopes = parse_scopes(required_scopes) if required_scopes else None

    logger.info(f"Creating bearer-only JWTVerifier for issuer: {issuer}")
    logger.debug(f"JWKS URI: {jwks_uri}")
    logger.debug(f"Algorithm: {algorithm}")
    logger.debug(f"Required scopes: {parsed_scopes}")
    logger.debug(f"Audience: {audience}")

    return LoggingJWTVerifier(
        jwks_uri=jwks_uri,
        issuer=issuer,
        algorithm=algorithm,
        required_scopes=parsed_scopes,
        audience=audience,
    )


def get_auth_provider(
    provider_type: AuthProviderType | str | None = None,
    base_url: str | None = None,
    required_scopes: list[str] | None = None,
    # Keycloak-specific
    keycloak_realm_url: str | None = None,
    # OBP-OIDC-specific
    obp_oidc_issuer_url: str | None = None,
    audience: str | list[str] | None = None,
) -> RemoteAuthProvider | TokenVerifier | None:
    """Factory function to create the appropriate authentication provider.

    This function reads configuration from environment variables if not explicitly provided.

    Environment Variables:
        - ENABLE_OAUTH: Set to "true" to enable OAuth (default: "false")
        - AUTH_PROVIDER: Provider type - "keycloak", "obp-oidc", or "bearer-only" (default: "keycloak")
        - BASE_URL: Public URL of the FastMCP server
        - KEYCLOAK_REALM_URL: Keycloak realm URL (for Keycloak provider, or bearer-only multi-issuer)
        - OBP_OIDC_ISSUER_URL: OBP-OIDC issuer URL (for OBP-OIDC, or bearer-only)
        - JWKS_URI: JWKS endpoint URL (for bearer-only single-issuer, defaults to {issuer}/jwks)

    For bearer-only mode with MULTIPLE identity providers:
        - Set both KEYCLOAK_REALM_URL and OBP_OIDC_ISSUER_URL
        - The server will accept tokens from either provider
        - Uses MultiIssuerJWTVerifier internally

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

        # Explicit configuration with single issuer
        auth = get_auth_provider(
            provider_type=AuthProviderType.BEARER_ONLY,
            obp_oidc_issuer_url="http://localhost:9000/obp-oidc",
            required_scopes=["openid", "profile"],
        )

        # Multi-issuer bearer-only (via env vars)
        # KEYCLOAK_REALM_URL=http://localhost:8080/realms/fastmcp
        # OBP_OIDC_ISSUER_URL=http://localhost:9000/obp-oidc
        # AUTH_PROVIDER=bearer-only
        auth = get_auth_provider()

        mcp = FastMCP("My Server", auth=auth)
        ```
    """
    # Check if OAuth is enabled
    enable_oauth = os.getenv("ENABLE_OAUTH", "false").lower() == "true"
    logger.info(f"🔐 Initializing authentication provider (ENABLE_OAUTH={enable_oauth})")
    
    if not enable_oauth:
        logger.info("OAuth is disabled; running in unauthenticated mode.")
        return None

    logger.info("OAuth is enabled; setting up authentication.")

    # Determine provider type
    if provider_type is None:
        provider_type = os.getenv("AUTH_PROVIDER", "keycloak").lower()
        logger.debug(f"Provider type from env: {provider_type}")
    else:
        logger.debug(f"Provider type from argument: {provider_type}")
    
    if isinstance(provider_type, str):
        try:
            provider_type = AuthProviderType(provider_type)
        except ValueError:
            logger.error(f"Invalid provider type: {provider_type}")
            raise ValueError(f"Unknown auth provider type: {provider_type}. Valid options: {[e.value for e in AuthProviderType]}")

    logger.info(f"Selected auth provider type: {provider_type.value}")

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

    elif provider_type == AuthProviderType.BEARER_ONLY:
        # For bearer-only, we validate tokens without exposing OAuth endpoints
        # This is the simplest and most appropriate for frontend-driven OAuth
        
        logger.info("Configuring bearer-only authentication (token validation only)")
        
        # Get issuer URLs from env vars if not provided as args
        keycloak_url = keycloak_realm_url or os.getenv("KEYCLOAK_REALM_URL")
        obp_oidc_url = obp_oidc_issuer_url or os.getenv("OBP_OIDC_ISSUER_URL")
        jwks_uri = os.getenv("JWKS_URI")
        
        logger.debug(f"Keycloak URL: {keycloak_url}")
        logger.debug(f"OBP-OIDC URL: {obp_oidc_url}")
        logger.debug(f"JWKS URI: {jwks_uri}")
        
        # Build list of configured issuers
        issuers: list[IssuerConfig] = []
        
        if keycloak_url:
            issuers.append(IssuerConfig(
                issuer=keycloak_url,
                jwks_uri=f"{keycloak_url}/protocol/openid-connect/certs",
                audience=audience,
            ))
            logger.info(f"Bearer-only: Added Keycloak issuer: {keycloak_url}")
        
        if obp_oidc_url:
            issuers.append(IssuerConfig(
                issuer=obp_oidc_url,
                jwks_uri=f"{obp_oidc_url}/jwks",
                audience=audience,
            ))
            logger.info(f"Bearer-only: Added OBP-OIDC issuer: {obp_oidc_url}")
        
        # If only JWKS_URI is provided (no issuer URLs), use single-issuer verifier
        if not issuers and jwks_uri:
            issuer = jwks_uri.rsplit('/jwks', 1)[0].rsplit('/certs', 1)[0].rsplit('/protocol/openid-connect', 1)[0]
            logger.info(f"Configuring bearer-only auth (single issuer) with JWKS: {jwks_uri}")
            return create_bearer_auth(
                jwks_uri=jwks_uri,
                issuer=issuer,
                required_scopes=required_scopes,
                audience=audience,
            )
        
        if not issuers:
            raise ValueError(
                "At least one of KEYCLOAK_REALM_URL, OBP_OIDC_ISSUER_URL, or JWKS_URI "
                "must be set when using bearer-only provider."
            )
        
        # Single issuer - use simple JWTVerifier
        if len(issuers) == 1:
            config = issuers[0]
            logger.info(f"Configuring bearer-only auth (single issuer): {config.issuer}")
            return create_bearer_auth(
                jwks_uri=config.jwks_uri,
                issuer=config.issuer,
                required_scopes=required_scopes,
                audience=config.audience,
            )
        
        # Multiple issuers - use MultiIssuerJWTVerifier
        logger.info(f"Configuring bearer-only auth with {len(issuers)} issuers (multi-issuer mode)")
        return MultiIssuerJWTVerifier(
            issuers=issuers,
            required_scopes=required_scopes,
        )

    else:
        raise ValueError(f"Unknown auth provider type: {provider_type}")


# Convenience exports
__all__ = [
    "AuthProviderType",
    "IssuerConfig",
    "KeycloakAuthProvider",
    "LoggingJWTVerifier",
    "MultiIssuerJWTVerifier",
    "OBPOIDCAuthProvider",
    "create_bearer_auth",
    "get_auth_provider",
]
