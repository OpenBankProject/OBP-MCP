"""Pytest configuration and shared fixtures for OBP-MCP tests."""

import os
import pytest


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure a clean environment for each test by removing auth-related env vars."""
    auth_env_vars = [
        "ENABLE_OAUTH",
        "AUTH_PROVIDER",
        "BASE_URL",
        "KEYCLOAK_REALM_URL",
        "OBP_OIDC_ISSUER_URL",
        "JWKS_URI",
    ]
    for var in auth_env_vars:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def keycloak_realm_url():
    """Sample Keycloak realm URL for tests."""
    return "http://localhost:8080/realms/fastmcp"


@pytest.fixture
def obp_oidc_issuer_url():
    """Sample OBP-OIDC issuer URL for tests."""
    return "http://localhost:9000/obp-oidc"


@pytest.fixture
def base_url():
    """Sample base URL for tests."""
    return "http://localhost:8000"


@pytest.fixture
def sample_jwt_payload():
    """Sample JWT payload for testing."""
    return {
        "iss": "http://localhost:8080/realms/fastmcp",
        "sub": "user123",
        "aud": "test-client",
        "exp": 9999999999,
        "iat": 1700000000,
        "scope": "openid profile email",
    }
