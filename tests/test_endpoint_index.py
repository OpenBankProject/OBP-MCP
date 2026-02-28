"""Tests for endpoint index module with Pydantic models."""

import pytest
import json
from typing import Dict, Any

from src.tools.endpoint_index import (
    EndpointIndex,
    EndpointSummary,
    EndpointSchema,
    EndpointParameter,
    EndpointResponse,
    RoleRequirement,
    HttpMethod,
    get_endpoint_index,
)


class TestHttpMethod:
    """Tests for HttpMethod enum."""

    def test_all_methods_exist(self):
        """Test that all standard HTTP methods are defined."""
        assert HttpMethod.GET == "GET"
        assert HttpMethod.POST == "POST"
        assert HttpMethod.PUT == "PUT"
        assert HttpMethod.DELETE == "DELETE"
        assert HttpMethod.PATCH == "PATCH"
        assert HttpMethod.HEAD == "HEAD"
        assert HttpMethod.OPTIONS == "OPTIONS"

    def test_method_from_string(self):
        """Test creating HttpMethod from string."""
        assert HttpMethod("GET") == HttpMethod.GET
        assert HttpMethod("POST") == HttpMethod.POST


class TestEndpointSummary:
    """Tests for EndpointSummary Pydantic model."""

    def test_create_summary(self):
        """Test creating an endpoint summary."""
        summary = EndpointSummary(
            id="test-endpoint",
            method=HttpMethod.GET,
            path="/test/path",
            operation_id="test-op",
            summary="Test endpoint",
            tags=["Test", "API"],
        )
        assert summary.id == "test-endpoint"
        assert summary.method == HttpMethod.GET
        assert summary.path == "/test/path"
        assert summary.operation_id == "test-op"
        assert summary.summary == "Test endpoint"
        assert summary.tags == ["Test", "API"]

    def test_summary_defaults(self):
        """Test endpoint summary with default values."""
        summary = EndpointSummary(
            id="test-endpoint",
            method=HttpMethod.POST,
            path="/test",
        )
        assert summary.operation_id == ""
        assert summary.summary == ""
        assert summary.tags == []

    def test_summary_serialization(self):
        """Test that summary serializes to JSON correctly."""
        summary = EndpointSummary(
            id="test-endpoint",
            method=HttpMethod.GET,
            path="/test/path",
            tags=["Test"],
        )
        data = summary.model_dump()
        # Method should be serialized as string value
        assert data["method"] == "GET"
        assert isinstance(data["method"], str)
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert "test-endpoint" in json_str

    def test_summary_from_dict(self):
        """Test creating summary from dictionary (like from JSON)."""
        data = {
            "id": "OBPv4.0.0-getBanks",
            "method": "GET",
            "path": "/obp/v6.0.0/banks",
            "operation_id": "OBPv4.0.0-getBanks",
            "summary": "Get Banks",
            "tags": ["Bank", "PSD2"],
        }
        summary = EndpointSummary(**data)
        assert summary.id == "OBPv4.0.0-getBanks"
        assert summary.method == HttpMethod.GET


class TestRoleRequirement:
    """Tests for RoleRequirement Pydantic model."""

    def test_create_role(self):
        """Test creating a role requirement."""
        role = RoleRequirement(
            role="CanGetBanks",
            requires_bank_id=False,
        )
        assert role.role == "CanGetBanks"
        assert role.requires_bank_id is False

    def test_role_with_bank_id(self):
        """Test role that requires bank_id."""
        role = RoleRequirement(
            role="CanGetAccountsAtBank",
            requires_bank_id=True,
        )
        assert role.role == "CanGetAccountsAtBank"
        assert role.requires_bank_id is True

    def test_role_default_bank_id(self):
        """Test role defaults for requires_bank_id."""
        role = RoleRequirement(role="SomeRole")
        assert role.requires_bank_id is False

    def test_role_serialization(self):
        """Test that role serializes to JSON correctly."""
        role = RoleRequirement(
            role="CanCreateCustomer",
            requires_bank_id=True,
        )
        data = role.model_dump()
        assert data["role"] == "CanCreateCustomer"
        assert data["requires_bank_id"] is True


class TestEndpointParameter:
    """Tests for EndpointParameter Pydantic model."""

    def test_create_parameter(self):
        """Test creating an endpoint parameter."""
        param = EndpointParameter(
            name="bank_id",
            **{"in": "path"},  # 'in' is aliased to 'in_'
            description="The bank identifier",
            required=True,
        )
        assert param.name == "bank_id"
        assert param.in_ == "path"
        assert param.description == "The bank identifier"
        assert param.required is True

    def test_parameter_serialization_by_alias(self):
        """Test that parameter serializes with correct aliases."""
        param = EndpointParameter(
            name="limit",
            **{"in": "query"},
            required=False,
        )
        data = param.model_dump(by_alias=True)
        # Should use 'in' not 'in_' in serialized form
        assert "in" in data
        assert data["in"] == "query"


class TestEndpointSchema:
    """Tests for EndpointSchema Pydantic model."""

    def test_create_schema(self):
        """Test creating a full endpoint schema."""
        schema = EndpointSchema(
            path="/obp/v6.0.0/banks",
            method=HttpMethod.GET,
            operation_id="OBPv4.0.0-getBanks",
            summary="Get Banks",
            description="Get all banks",
            tags=["Bank"],
        )
        assert schema.path == "/obp/v6.0.0/banks"
        assert schema.method == HttpMethod.GET
        assert schema.tags == ["Bank"]

    def test_schema_defaults(self):
        """Test schema with default values."""
        schema = EndpointSchema(
            path="/test",
            method=HttpMethod.POST,
        )
        assert schema.operation_id == ""
        assert schema.summary == ""
        assert schema.description == ""
        assert schema.tags == []
        assert schema.parameters == []
        assert schema.requestBody is None
        assert schema.responses == {}
        assert schema.security == []
        assert schema.roles == []

    def test_schema_from_raw(self):
        """Test creating schema from raw dictionary data."""
        raw_data = {
            "path": "/obp/v6.0.0/banks/{BANK_ID}",
            "method": "GET",
            "operation_id": "OBPv5.0.0-getBank",
            "summary": "Get Bank",
            "description": "Get a specific bank by ID",
            "tags": ["Bank"],
            "parameters": [
                {
                    "name": "BANK_ID",
                    "in": "path",
                    "required": True,
                    "description": "The bank identifier",
                }
            ],
            "responses": {
                "200": {
                    "description": "Success",
                    "schema": {"$ref": "#/definitions/BankJSON"},
                },
                "400": {
                    "description": "Error",
                },
            },
        }
        schema = EndpointSchema.from_raw(raw_data)
        assert schema.path == "/obp/v6.0.0/banks/{BANK_ID}"
        assert schema.method == HttpMethod.GET
        assert len(schema.parameters) == 1
        assert schema.parameters[0].name == "BANK_ID"
        assert len(schema.responses) == 2
        assert schema.responses["200"].description == "Success"

    def test_schema_serialization(self):
        """Test that schema serializes to JSON correctly."""
        schema = EndpointSchema(
            path="/test",
            method=HttpMethod.DELETE,
            tags=["Test"],
        )
        data = schema.model_dump()
        assert data["method"] == "DELETE"
        
        # Should be JSON serializable
        json_str = json.dumps(data)
        assert "/test" in json_str


class TestEndpointIndex:
    """Tests for EndpointIndex class."""

    def test_get_global_index(self):
        """Test getting the global endpoint index."""
        index = get_endpoint_index()
        assert isinstance(index, EndpointIndex)
        # Should have loaded endpoints from the JSON file
        assert len(index._index) > 0

    def test_list_endpoints_returns_typed_models(self):
        """Test that list_endpoints_by_tag returns typed EndpointSummary models."""
        index = get_endpoint_index()
        endpoints = index.list_endpoints_by_tag(["Bank"])
        
        assert len(endpoints) > 0
        for ep in endpoints:
            assert isinstance(ep, EndpointSummary)
            # Method is stored as string value due to use_enum_values=True
            assert ep.method in [m.value for m in HttpMethod]
            assert isinstance(ep.tags, list)

    def test_list_endpoints_raw_returns_dicts(self):
        """Test that list_endpoints_by_tag_raw returns dictionaries."""
        index = get_endpoint_index()
        endpoints = index.list_endpoints_by_tag_raw(["Bank"])
        
        assert len(endpoints) > 0
        for ep in endpoints:
            assert isinstance(ep, dict)
            assert "id" in ep
            assert "method" in ep

    def test_get_endpoint_schema_returns_typed_model(self):
        """Test that get_endpoint_schema returns typed EndpointSchema model."""
        index = get_endpoint_index()
        endpoints = index.list_endpoints_by_tag(["Bank"])
        
        if endpoints:
            schema = index.get_endpoint_schema(endpoints[0].id)
            assert schema is not None
            assert isinstance(schema, EndpointSchema)
            # Method is stored as string value due to use_enum_values=True
            assert schema.method in [m.value for m in HttpMethod]
            assert isinstance(schema.parameters, list)
            for param in schema.parameters:
                assert isinstance(param, EndpointParameter)

    def test_get_endpoint_schema_raw_returns_dict(self):
        """Test that get_endpoint_schema_raw returns dictionary."""
        index = get_endpoint_index()
        endpoints = index.list_endpoints_by_tag_raw(["Bank"])
        
        if endpoints:
            schema = index.get_endpoint_schema_raw(endpoints[0]["id"])
            assert schema is not None
            assert isinstance(schema, dict)

    def test_get_endpoint_by_id_returns_typed_model(self):
        """Test that get_endpoint_by_id returns typed EndpointSummary model."""
        index = get_endpoint_index()
        endpoint = index.get_endpoint_by_id("OBPv4.0.0-getBanks")
        
        if endpoint:
            assert isinstance(endpoint, EndpointSummary)
            assert endpoint.id == "OBPv4.0.0-getBanks"

    def test_get_endpoint_by_id_raw_returns_dict(self):
        """Test that get_endpoint_by_id_raw returns dictionary."""
        index = get_endpoint_index()
        endpoint = index.get_endpoint_by_id_raw("OBPv4.0.0-getBanks")
        
        if endpoint:
            assert isinstance(endpoint, dict)
            assert endpoint["id"] == "OBPv4.0.0-getBanks"

    def test_get_nonexistent_endpoint(self):
        """Test getting a non-existent endpoint returns None."""
        index = get_endpoint_index()
        assert index.get_endpoint_by_id("nonexistent-endpoint") is None
        assert index.get_endpoint_schema("nonexistent-endpoint") is None

    def test_empty_tags_returns_all_endpoints(self):
        """Test that empty tags list returns all endpoints."""
        index = get_endpoint_index()
        all_endpoints = index.list_endpoints_by_tag([])
        assert len(all_endpoints) == len(index._index)

    def test_get_all_tags(self):
        """Test getting all unique tags."""
        index = get_endpoint_index()
        tags = index.get_all_tags()
        
        assert isinstance(tags, list)
        assert len(tags) > 0
        # Should be sorted
        assert tags == sorted(tags)


class TestBuildFromResourceDocs:
    """Tests for building index from resource docs format."""

    def test_build_from_resource_docs(self, tmp_path):
        """Test building index from resource docs data."""
        # Create a temporary index
        index_file = tmp_path / "test_index.json"
        schemas_file = tmp_path / "test_schemas.json"
        
        index = EndpointIndex(
            index_file=str(index_file),
            schemas_file=str(schemas_file)
        )
        
        # Sample resource docs data
        resource_docs_data = {
            "resource_docs": [
                {
                    "operation_id": "OBPv6.0.0-testEndpoint",
                    "request_verb": "GET",
                    "request_url": "/obp/v6.0.0/test",
                    "summary": "Test Endpoint",
                    "description": "<p>Test description</p>",
                    "description_markdown": "Test description",
                    "tags": ["Test", "API"],
                    "roles": [
                        {"role": "CanTestEndpoint", "requires_bank_id": False}
                    ],
                    "success_response_body": {"status": "ok"},
                    "error_response_bodies": ["OBP-20001: User not logged in."],
                    "typed_success_response_body": {
                        "type": "object",
                        "properties": {"status": {"type": "string"}}
                    },
                    "is_featured": True,
                    "special_instructions": "",
                    "connector_methods": []
                },
                {
                    "operation_id": "OBPv6.0.0-anotherEndpoint",
                    "request_verb": "POST",
                    "request_url": "/obp/v6.0.0/another",
                    "summary": "Another Endpoint",
                    "description": "Another description",
                    "tags": ["Test"],
                    "roles": [],
                }
            ]
        }
        
        index.build_index_from_resource_docs(resource_docs_data)
        
        # Verify index was built
        assert len(index._index) == 2
        assert len(index._schemas) == 2
        
        # Verify first endpoint
        endpoint = index.get_endpoint_by_id("OBPv6.0.0-testEndpoint")
        assert endpoint is not None
        assert endpoint.method == "GET"
        assert endpoint.path == "/obp/v6.0.0/test"
        assert "Test" in endpoint.tags
        
        # Verify schema with roles
        schema = index.get_endpoint_schema("OBPv6.0.0-testEndpoint")
        assert schema is not None
        assert len(schema.roles) == 1
        assert schema.roles[0].role == "CanTestEndpoint"
        assert schema.roles[0].requires_bank_id is False
        assert schema.is_featured is True
        assert schema.success_response_body == {"status": "ok"}

    def test_build_from_resource_docs_with_no_roles(self, tmp_path):
        """Test building index from resource docs with endpoints that have no roles."""
        index_file = tmp_path / "test_index.json"
        schemas_file = tmp_path / "test_schemas.json"
        
        index = EndpointIndex(
            index_file=str(index_file),
            schemas_file=str(schemas_file)
        )
        
        resource_docs_data = {
            "resource_docs": [
                {
                    "operation_id": "OBPv6.0.0-publicEndpoint",
                    "request_verb": "GET",
                    "request_url": "/obp/v6.0.0/public",
                    "summary": "Public Endpoint",
                    "tags": ["Public"],
                    "roles": [],  # No roles required
                }
            ]
        }
        
        index.build_index_from_resource_docs(resource_docs_data)
        
        schema = index.get_endpoint_schema("OBPv6.0.0-publicEndpoint")
        assert schema is not None
        assert len(schema.roles) == 0

    def test_schema_from_raw_with_roles(self):
        """Test creating EndpointSchema from raw data with roles."""
        raw_data = {
            "path": "/test",
            "method": "GET",
            "operation_id": "test-op",
            "summary": "Test",
            "roles": [
                {"role": "CanDoThing", "requires_bank_id": True},
                {"role": "CanDoOtherThing", "requires_bank_id": False},
            ]
        }
        
        schema = EndpointSchema.from_raw(raw_data)
        assert len(schema.roles) == 2
        assert schema.roles[0].role == "CanDoThing"
        assert schema.roles[0].requires_bank_id is True
        assert schema.roles[1].role == "CanDoOtherThing"
        assert schema.roles[1].requires_bank_id is False
