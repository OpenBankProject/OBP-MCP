"""Unit tests for the auth module.

Tests for authentication providers:
- IssuerConfig
- MultiIssuerJWTVerifier
- create_bearer_auth()
- get_auth_provider()
- KeycloakAuthProvider
- OBPOIDCAuthProvider
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import jwt as pyjwt
from fastmcp.server.auth.providers.jwt import JWTVerifier

from src.mcp_server_obp.auth import (
    AuthProviderType,
    IssuerConfig,
    KeycloakAuthProvider,
    MultiIssuerJWTVerifier,
    OBPOIDCAuthProvider,
    create_bearer_auth,
    get_auth_provider,
)


class TestIssuerConfig:
    """Tests for IssuerConfig dataclass."""

    def test_issuer_config_creation(self):
        """Test creating an IssuerConfig with all parameters."""
        config = IssuerConfig(
            issuer="http://localhost:8080/realms/test",
            jwks_uri="http://localhost:8080/realms/test/protocol/openid-connect/certs",
            algorithm="RS256",
            audience="test-client",
        )

        assert config.issuer == "http://localhost:8080/realms/test"
        assert config.jwks_uri == "http://localhost:8080/realms/test/protocol/openid-connect/certs"
        assert config.algorithm == "RS256"
        assert config.audience == "test-client"

    def test_issuer_config_defaults(self):
        """Test IssuerConfig default values."""
        config = IssuerConfig(
            issuer="http://localhost:9000/obp-oidc",
            jwks_uri="http://localhost:9000/obp-oidc/jwks",
        )

        assert config.algorithm == "RS256"
        assert config.audience is None

    def test_issuer_config_audience_list(self):
        """Test IssuerConfig with audience as a list."""
        config = IssuerConfig(
            issuer="http://localhost:8080/realms/test",
            jwks_uri="http://localhost:8080/realms/test/certs",
            audience=["client1", "client2"],
        )

        assert config.audience == ["client1", "client2"]


class TestMultiIssuerJWTVerifier:
    """Tests for MultiIssuerJWTVerifier class."""

    def test_initialization_with_single_issuer(self, keycloak_realm_url):
        """Test MultiIssuerJWTVerifier initialization with a single issuer."""
        verifier = MultiIssuerJWTVerifier(
            issuers=[
                IssuerConfig(
                    issuer=keycloak_realm_url,
                    jwks_uri=f"{keycloak_realm_url}/protocol/openid-connect/certs",
                )
            ],
            required_scopes=["openid", "profile"],
        )

        assert len(verifier._verifiers) == 1
        assert keycloak_realm_url in verifier._verifiers
        assert verifier.required_scopes == ["openid", "profile"]

    def test_initialization_with_multiple_issuers(self, keycloak_realm_url, obp_oidc_issuer_url):
        """Test MultiIssuerJWTVerifier initialization with multiple issuers."""
        verifier = MultiIssuerJWTVerifier(
            issuers=[
                IssuerConfig(
                    issuer=keycloak_realm_url,
                    jwks_uri=f"{keycloak_realm_url}/protocol/openid-connect/certs",
                ),
                IssuerConfig(
                    issuer=obp_oidc_issuer_url,
                    jwks_uri=f"{obp_oidc_issuer_url}/jwks",
                ),
            ],
            required_scopes=["openid"],
        )

        assert len(verifier._verifiers) == 2
        assert keycloak_realm_url in verifier._verifiers
        assert obp_oidc_issuer_url in verifier._verifiers

    def test_initialization_empty_issuers_raises_error(self):
        """Test that initializing with empty issuers list raises ValueError."""
        with pytest.raises(ValueError, match="At least one issuer must be configured"):
            MultiIssuerJWTVerifier(issuers=[], required_scopes=["openid"])

    def test_extract_issuer_valid_token(self, sample_jwt_payload, keycloak_realm_url):
        """Test extracting issuer from a valid JWT token."""
        verifier = MultiIssuerJWTVerifier(
            issuers=[
                IssuerConfig(
                    issuer=keycloak_realm_url,
                    jwks_uri=f"{keycloak_realm_url}/certs",
                )
            ]
        )

        # Create a token (not signed, we're just testing payload extraction)
        token = pyjwt.encode(sample_jwt_payload, "secret", algorithm="HS256")
        issuer = verifier._extract_issuer(token)

        assert issuer == sample_jwt_payload["iss"]

    def test_extract_issuer_invalid_token(self, keycloak_realm_url):
        """Test extracting issuer from an invalid token returns None."""
        verifier = MultiIssuerJWTVerifier(
            issuers=[
                IssuerConfig(
                    issuer=keycloak_realm_url,
                    jwks_uri=f"{keycloak_realm_url}/certs",
                )
            ]
        )

        issuer = verifier._extract_issuer("not-a-valid-jwt")
        assert issuer is None

    @pytest.mark.asyncio
    async def test_verify_token_with_known_issuer(self, sample_jwt_payload, keycloak_realm_url):
        """Test token verification when issuer is known."""
        token = pyjwt.encode(sample_jwt_payload, "secret", algorithm="HS256")

        # Create verifier with mocked JWTVerifier
        with patch("src.mcp_server_obp.auth.JWTVerifier") as MockJWTVerifier:
            mock_verifier = AsyncMock()
            mock_verifier.verify_token = AsyncMock(return_value={"sub": "user123"})
            MockJWTVerifier.return_value = mock_verifier

            verifier = MultiIssuerJWTVerifier(
                issuers=[
                    IssuerConfig(
                        issuer=keycloak_realm_url,
                        jwks_uri=f"{keycloak_realm_url}/certs",
                    )
                ]
            )

            # Replace the verifier with our mock
            verifier._verifiers[keycloak_realm_url] = mock_verifier

            result = await verifier.verify_token(token)

            assert result == {"sub": "user123"}
            mock_verifier.verify_token.assert_called_once_with(token)

    @pytest.mark.asyncio
    async def test_verify_token_unknown_issuer_tries_all(self, keycloak_realm_url, obp_oidc_issuer_url):
        """Test that unknown issuer tries all verifiers."""
        # Token with unknown issuer
        payload = {
            "iss": "http://unknown-issuer.com",
            "sub": "user123",
            "exp": 9999999999,
        }
        token = pyjwt.encode(payload, "secret", algorithm="HS256")

        with patch("src.mcp_server_obp.auth.JWTVerifier") as MockJWTVerifier:
            # First verifier fails
            mock_verifier1 = AsyncMock()
            mock_verifier1.verify_token = AsyncMock(return_value=None)

            # Second verifier succeeds
            mock_verifier2 = AsyncMock()
            mock_verifier2.verify_token = AsyncMock(return_value={"sub": "user123"})

            MockJWTVerifier.side_effect = [mock_verifier1, mock_verifier2]

            verifier = MultiIssuerJWTVerifier(
                issuers=[
                    IssuerConfig(issuer=keycloak_realm_url, jwks_uri=f"{keycloak_realm_url}/certs"),
                    IssuerConfig(issuer=obp_oidc_issuer_url, jwks_uri=f"{obp_oidc_issuer_url}/jwks"),
                ]
            )

            # Replace verifiers with our mocks
            verifier._verifiers[keycloak_realm_url] = mock_verifier1
            verifier._verifiers[obp_oidc_issuer_url] = mock_verifier2

            result = await verifier.verify_token(token)

            assert result == {"sub": "user123"}
            mock_verifier1.verify_token.assert_called_once_with(token)
            mock_verifier2.verify_token.assert_called_once_with(token)

    @pytest.mark.asyncio
    async def test_verify_token_rejects_non_jwt_without_verifiers(self, keycloak_realm_url):
        """Ensure malformed tokens fail fast without hitting any verifier."""
        bad_token = "not-a-jwt"

        with patch("src.mcp_server_obp.auth.JWTVerifier") as MockJWTVerifier:
            mock_verifier = AsyncMock()
            mock_verifier.verify_token = AsyncMock(return_value={"sub": "user123"})
            MockJWTVerifier.return_value = mock_verifier

            verifier = MultiIssuerJWTVerifier(
                issuers=[
                    IssuerConfig(
                        issuer=keycloak_realm_url,
                        jwks_uri=f"{keycloak_realm_url}/certs",
                    )
                ]
            )

            # Replace the verifier with our mock
            verifier._verifiers[keycloak_realm_url] = mock_verifier

            result = await verifier.verify_token(bad_token)

            assert result is None
            mock_verifier.verify_token.assert_not_called()


class TestCreateBearerAuth:
    """Tests for create_bearer_auth() function."""

    def test_create_bearer_auth_basic(self, obp_oidc_issuer_url):
        """Test creating a basic bearer auth verifier."""
        verifier = create_bearer_auth(
            jwks_uri=f"{obp_oidc_issuer_url}/jwks",
            issuer=obp_oidc_issuer_url,
        )

        assert isinstance(verifier, JWTVerifier)

    def test_create_bearer_auth_with_scopes(self, obp_oidc_issuer_url):
        """Test creating a bearer auth verifier with required scopes."""
        verifier = create_bearer_auth(
            jwks_uri=f"{obp_oidc_issuer_url}/jwks",
            issuer=obp_oidc_issuer_url,
            required_scopes=["openid", "profile"],
        )

        assert isinstance(verifier, JWTVerifier)

    def test_create_bearer_auth_with_audience(self, obp_oidc_issuer_url):
        """Test creating a bearer auth verifier with audience."""
        verifier = create_bearer_auth(
            jwks_uri=f"{obp_oidc_issuer_url}/jwks",
            issuer=obp_oidc_issuer_url,
            audience="test-client",
        )

        assert isinstance(verifier, JWTVerifier)

    def test_create_bearer_auth_with_algorithm(self, obp_oidc_issuer_url):
        """Test creating a bearer auth verifier with custom algorithm."""
        verifier = create_bearer_auth(
            jwks_uri=f"{obp_oidc_issuer_url}/jwks",
            issuer=obp_oidc_issuer_url,
            algorithm="ES256",
        )

        assert isinstance(verifier, JWTVerifier)


class TestGetAuthProvider:
    """Tests for get_auth_provider() function."""

    def test_oauth_disabled_returns_none(self, monkeypatch):
        """Test that OAuth disabled returns None."""
        monkeypatch.setenv("ENABLE_OAUTH", "false")
        result = get_auth_provider()
        assert result is None

    def test_oauth_disabled_by_default(self):
        """Test that OAuth is disabled by default (no env var)."""
        result = get_auth_provider()
        assert result is None

    def test_auth_provider_none_returns_none(self, monkeypatch, base_url):
        """Test that AUTH_PROVIDER=none returns None."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "none")
        monkeypatch.setenv("BASE_URL", base_url)

        result = get_auth_provider()
        assert result is None

    def test_missing_base_url_raises_error(self, monkeypatch):
        """Test that enabling OAuth without BASE_URL raises error."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")

        with pytest.raises(ValueError, match="BASE_URL must be set"):
            get_auth_provider()

    def test_invalid_provider_type_raises_error(self, monkeypatch, base_url):
        """Test that invalid provider type raises error."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "invalid-provider")
        monkeypatch.setenv("BASE_URL", base_url)

        with pytest.raises(ValueError, match="Unknown auth provider type"):
            get_auth_provider()

    def test_keycloak_provider_creation(self, monkeypatch, base_url, keycloak_realm_url):
        """Test creating Keycloak provider from environment variables."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "keycloak")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("KEYCLOAK_REALM_URL", keycloak_realm_url)

        result = get_auth_provider()
        assert isinstance(result, KeycloakAuthProvider)

    def test_keycloak_provider_missing_realm_url_raises_error(self, monkeypatch, base_url):
        """Test that Keycloak provider without realm URL raises error."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "keycloak")
        monkeypatch.setenv("BASE_URL", base_url)

        with pytest.raises(ValueError, match="KEYCLOAK_REALM_URL must be set"):
            get_auth_provider()

    def test_obp_oidc_provider_creation(self, monkeypatch, base_url, obp_oidc_issuer_url):
        """Test creating OBP-OIDC provider from environment variables."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "obp-oidc")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("OBP_OIDC_ISSUER_URL", obp_oidc_issuer_url)

        result = get_auth_provider()
        assert isinstance(result, OBPOIDCAuthProvider)

    def test_obp_oidc_provider_missing_issuer_url_raises_error(self, monkeypatch, base_url):
        """Test that OBP-OIDC provider without issuer URL raises error."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "obp-oidc")
        monkeypatch.setenv("BASE_URL", base_url)

        with pytest.raises(ValueError, match="OBP_OIDC_ISSUER_URL must be set"):
            get_auth_provider()

    def test_bearer_only_single_issuer_keycloak(self, monkeypatch, base_url, keycloak_realm_url):
        """Test bearer-only mode with single Keycloak issuer."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "bearer-only")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("KEYCLOAK_REALM_URL", keycloak_realm_url)

        result = get_auth_provider()
        assert isinstance(result, JWTVerifier)

    def test_bearer_only_single_issuer_obp_oidc(self, monkeypatch, base_url, obp_oidc_issuer_url):
        """Test bearer-only mode with single OBP-OIDC issuer."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "bearer-only")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("OBP_OIDC_ISSUER_URL", obp_oidc_issuer_url)

        result = get_auth_provider()
        assert isinstance(result, JWTVerifier)

    def test_bearer_only_multi_issuer(self, monkeypatch, base_url, keycloak_realm_url, obp_oidc_issuer_url):
        """Test bearer-only mode with multiple issuers."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "bearer-only")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("KEYCLOAK_REALM_URL", keycloak_realm_url)
        monkeypatch.setenv("OBP_OIDC_ISSUER_URL", obp_oidc_issuer_url)

        result = get_auth_provider()
        assert isinstance(result, MultiIssuerJWTVerifier)
        assert len(result._verifiers) == 2

    def test_bearer_only_with_jwks_uri(self, monkeypatch, base_url):
        """Test bearer-only mode with JWKS_URI only."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "bearer-only")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("JWKS_URI", "http://localhost:9000/obp-oidc/jwks")

        result = get_auth_provider()
        assert isinstance(result, JWTVerifier)

    def test_bearer_only_no_issuer_raises_error(self, monkeypatch, base_url):
        """Test bearer-only mode without any issuer configuration raises error."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "bearer-only")
        monkeypatch.setenv("BASE_URL", base_url)

        with pytest.raises(ValueError, match="At least one of KEYCLOAK_REALM_URL"):
            get_auth_provider()

    def test_explicit_provider_type_enum(self, monkeypatch, base_url, keycloak_realm_url):
        """Test providing provider type as AuthProviderType enum."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("BASE_URL", base_url)
        monkeypatch.setenv("KEYCLOAK_REALM_URL", keycloak_realm_url)

        result = get_auth_provider(provider_type=AuthProviderType.KEYCLOAK)
        assert isinstance(result, KeycloakAuthProvider)

    def test_explicit_parameters_override_env(self, monkeypatch, base_url, keycloak_realm_url, obp_oidc_issuer_url):
        """Test that explicit parameters override environment variables."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")
        monkeypatch.setenv("AUTH_PROVIDER", "keycloak")
        monkeypatch.setenv("KEYCLOAK_REALM_URL", keycloak_realm_url)

        # Override with OBP-OIDC via explicit parameters
        result = get_auth_provider(
            provider_type=AuthProviderType.OBP_OIDC,
            base_url=base_url,
            obp_oidc_issuer_url=obp_oidc_issuer_url,
        )
        assert isinstance(result, OBPOIDCAuthProvider)

    def test_custom_required_scopes(self, monkeypatch, base_url, obp_oidc_issuer_url):
        """Test providing custom required scopes."""
        monkeypatch.setenv("ENABLE_OAUTH", "true")

        result = get_auth_provider(
            provider_type=AuthProviderType.OBP_OIDC,
            base_url=base_url,
            obp_oidc_issuer_url=obp_oidc_issuer_url,
            required_scopes=["custom", "scopes"],
        )
        assert isinstance(result, OBPOIDCAuthProvider)


class TestKeycloakAuthProvider:
    """Tests for KeycloakAuthProvider class."""

    def test_initialization(self, base_url, keycloak_realm_url):
        """Test KeycloakAuthProvider initialization."""
        provider = KeycloakAuthProvider(
            realm_url=keycloak_realm_url,
            base_url=base_url,
        )

        assert provider.realm_url == keycloak_realm_url
        assert str(provider.base_url).rstrip('/') == base_url.rstrip('/')

    def test_initialization_with_scopes(self, base_url, keycloak_realm_url):
        """Test KeycloakAuthProvider with required scopes."""
        provider = KeycloakAuthProvider(
            realm_url=keycloak_realm_url,
            base_url=base_url,
            required_scopes=["openid", "profile"],
        )

        assert provider.realm_url == keycloak_realm_url

    def test_get_routes_includes_metadata_and_register(self, base_url, keycloak_realm_url):
        """Test that get_routes includes metadata and register endpoints."""
        provider = KeycloakAuthProvider(
            realm_url=keycloak_realm_url,
            base_url=base_url,
        )

        routes = provider.get_routes()
        route_paths = [route.path for route in routes]

        assert "/.well-known/oauth-authorization-server" in route_paths
        assert "/register" in route_paths


class TestOBPOIDCAuthProvider:
    """Tests for OBPOIDCAuthProvider class."""

    def test_initialization(self, base_url, obp_oidc_issuer_url):
        """Test OBPOIDCAuthProvider initialization."""
        provider = OBPOIDCAuthProvider(
            issuer_url=obp_oidc_issuer_url,
            base_url=base_url,
        )

        assert provider.issuer_url == obp_oidc_issuer_url
        assert str(provider.base_url).rstrip('/') == base_url.rstrip('/')

    def test_initialization_with_scopes(self, base_url, obp_oidc_issuer_url):
        """Test OBPOIDCAuthProvider with required scopes."""
        provider = OBPOIDCAuthProvider(
            issuer_url=obp_oidc_issuer_url,
            base_url=base_url,
            required_scopes=["openid", "profile", "email"],
        )

        assert provider.issuer_url == obp_oidc_issuer_url

    def test_get_routes_includes_forwarding_endpoints(self, base_url, obp_oidc_issuer_url):
        """Test that get_routes includes forwarding endpoints."""
        provider = OBPOIDCAuthProvider(
            issuer_url=obp_oidc_issuer_url,
            base_url=base_url,
        )

        routes = provider.get_routes()
        route_paths = [route.path for route in routes]

        assert "/.well-known/oauth-authorization-server" in route_paths
        assert "/.well-known/openid-configuration" in route_paths
        assert "/register" in route_paths
