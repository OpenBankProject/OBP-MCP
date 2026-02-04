"""
Endpoint Index Management for Hybrid Tag-Based Routing.

This module provides lightweight endpoint indexing with separate schema storage.
The lightweight index is used for discovery, while full schemas are stored 
separately and loaded on-demand.
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from enum import Enum

from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


# =============================================================================
# Pydantic Models for Type Safety
# =============================================================================


class HttpMethod(str, Enum):
    """HTTP methods supported by the API."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class EndpointSummary(BaseModel):
    """
    Lightweight endpoint summary for discovery and listing.
    
    This model contains minimal information needed for endpoint discovery
    without the full OpenAPI schema details.
    """
    id: str = Field(..., description="Unique identifier for the endpoint")
    method: HttpMethod = Field(..., description="HTTP method")
    path: str = Field(..., description="API path template")
    operation_id: str = Field(default="", description="OpenAPI operationId")
    summary: str = Field(default="", description="Brief description of the endpoint")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    
    model_config = {
        "frozen": False,
        "extra": "ignore",
        "use_enum_values": True,  # Serialize enums as their values
    }


class EndpointParameter(BaseModel):
    """
    OpenAPI parameter definition.
    
    Represents a single parameter for an API endpoint (path, query, header, etc.).
    """
    name: str = Field(..., description="Parameter name")
    in_: str = Field(..., alias="in", description="Parameter location (path, query, header, body)")
    description: str = Field(default="", description="Parameter description")
    required: bool = Field(default=False, description="Whether the parameter is required")
    schema_: Optional[Dict[str, Any]] = Field(default=None, alias="schema", description="JSON Schema for the parameter")
    type: Optional[str] = Field(default=None, description="Parameter type (for simple types)")
    
    model_config = {
        "populate_by_name": True,
        "extra": "allow",  # Allow extra fields from OpenAPI spec
    }


class EndpointResponse(BaseModel):
    """
    OpenAPI response definition.
    
    Represents a single response type for an API endpoint.
    """
    description: str = Field(default="", description="Response description")
    schema_: Optional[Dict[str, Any]] = Field(default=None, alias="schema", description="JSON Schema for the response body")
    
    model_config = {
        "populate_by_name": True,
        "extra": "allow",
    }


class SecurityRequirement(BaseModel):
    """
    OpenAPI security requirement.
    
    Represents authentication/authorization requirements for an endpoint.
    """
    directLogin: Optional[List[str]] = Field(default=None)
    gatewayLogin: Optional[List[str]] = Field(default=None)
    
    model_config = {
        "extra": "allow",
    }


class EndpointSchema(BaseModel):
    """
    Full OpenAPI schema for an endpoint.
    
    Contains complete specification including parameters, request body,
    responses, and security requirements.
    """
    path: str = Field(..., description="API path template")
    method: HttpMethod = Field(..., description="HTTP method")
    operation_id: str = Field(default="", description="OpenAPI operationId")
    summary: str = Field(default="", description="Brief description")
    description: str = Field(default="", description="Detailed description (may contain HTML)")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    parameters: List[EndpointParameter] = Field(default_factory=list, description="Endpoint parameters")
    requestBody: Optional[Dict[str, Any]] = Field(default=None, description="Request body specification")
    responses: Dict[str, EndpointResponse] = Field(default_factory=dict, description="Response specifications by status code")
    security: List[Dict[str, Any]] = Field(default_factory=list, description="Security requirements")
    roles: List[str] = Field(default_factory=list, description="Required roles")
    
    model_config = {
        "extra": "ignore",
        "use_enum_values": True,  # Serialize enums as their values
    }
    
    @classmethod
    def from_raw(cls, data: Dict[str, Any]) -> "EndpointSchema":
        """
        Create an EndpointSchema from raw dictionary data.
        
        Handles the conversion of nested structures and provides sensible defaults.
        """
        # Convert responses dict to use EndpointResponse models
        responses = {}
        for status_code, response_data in data.get("responses", {}).items():
            if isinstance(response_data, dict):
                responses[status_code] = EndpointResponse(**response_data)
            else:
                responses[status_code] = EndpointResponse(description=str(response_data))
        
        # Convert parameters to EndpointParameter models
        parameters = []
        for param_data in data.get("parameters", []):
            if isinstance(param_data, dict):
                parameters.append(EndpointParameter(**param_data))
        
        return cls(
            path=data.get("path", ""),
            method=HttpMethod(data.get("method", "GET").upper()),
            operation_id=data.get("operation_id", ""),
            summary=data.get("summary", ""),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            parameters=parameters,
            requestBody=data.get("requestBody"),
            responses=responses,
            security=data.get("security", []),
            roles=data.get("roles", []),
        )


class EndpointIndex:
    """
    Manages a lightweight index of API endpoints with separate schema storage.
    
    Index entries contain minimal information (id, name, method, path, summary, tags)
    while full schemas are stored in a separate file and loaded on-demand.
    
    This class provides both typed (Pydantic models) and raw (dict) access methods
    for flexibility in different use cases.
    """
    
    def __init__(self, index_file: Optional[str] = None, schemas_file: Optional[str] = None):
        """
        Initialize the endpoint index.
        
        Args:
            index_file: Path to the index JSON file. If None, uses default location.
            schemas_file: Path to the schemas JSON file. If None, uses default location.
        """
        if index_file is None:
            index_file = os.path.join(
                os.path.dirname(__file__), 
                "../../database/endpoint_index.json"
            )
        
        if schemas_file is None:
            schemas_file = os.path.join(
                os.path.dirname(__file__), 
                "../../database/endpoint_schemas.json"
            )
        
        self.index_file = Path(index_file).resolve()
        self.schemas_file = Path(schemas_file).resolve()
        self._index: Dict[str, Dict[str, Any]] = {}
        self._schemas: Dict[str, Dict[str, Any]] = {}  # On-demand loaded schemas
        self._schemas_loaded = False
        
        # Cached Pydantic model instances
        self._index_models: Dict[str, EndpointSummary] = {}
        self._schema_models: Dict[str, EndpointSchema] = {}
        
        # Load index if it exists
        if self.index_file.exists():
            self._load_index()
    
    def _load_index(self) -> None:
        """Load the endpoint index from disk."""
        try:
            with open(self.index_file, 'r') as f:
                data = json.load(f)
                self._index = data.get('endpoints', {})
                # Clear cached models when reloading
                self._index_models = {}
                logger.info(f"Loaded {len(self._index)} endpoints from index")
        except Exception as e:
            logger.error(f"Failed to load endpoint index: {e}")
            self._index = {}
            self._index_models = {}
    
    def _load_schemas(self) -> None:
        """Load endpoint schemas from disk (lazy loaded on first access)."""
        if self._schemas_loaded:
            return
        
        try:
            if self.schemas_file.exists():
                with open(self.schemas_file, 'r') as f:
                    self._schemas = json.load(f)
                # Clear cached models when reloading
                self._schema_models = {}
                logger.info(f"Loaded {len(self._schemas)} endpoint schemas")
            else:
                logger.warning(f"Schemas file not found: {self.schemas_file}")
                self._schemas = {}
        except Exception as e:
            logger.error(f"Failed to load endpoint schemas: {e}")
            self._schemas = {}
        
        self._schemas_loaded = True
    
    def _save_index(self) -> None:
        """Save the endpoint index to disk."""
        try:
            # Ensure directory exists
            self.index_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.index_file, 'w') as f:
                json.dump({'endpoints': self._index}, f, indent=2)
            logger.info(f"Saved {len(self._index)} endpoints to index")
        except Exception as e:
            logger.error(f"Failed to save endpoint index: {e}")
    
    def _save_schemas(self) -> None:
        """Save endpoint schemas to disk."""
        try:
            # Ensure directory exists
            self.schemas_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.schemas_file, 'w') as f:
                json.dump(self._schemas, f, indent=2)
            logger.info(f"Saved {len(self._schemas)} endpoint schemas")
        except Exception as e:
            logger.error(f"Failed to save endpoint schemas: {e}")
    
    def build_index_from_swagger(self, swagger_data: Dict[str, Any]) -> None:
        """
        Build the lightweight endpoint index and full schemas from swagger/OpenAPI data.
        
        Args:
            swagger_data: Swagger/OpenAPI specification as a dictionary
        """
        self._index = {}
        self._schemas = {}
        paths = swagger_data.get("paths", {})
        
        logger.info(f"Building index from {len(paths)} paths...")
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if not isinstance(details, dict):
                    continue
                
                # Extract minimal information for the index
                tags = details.get("tags", [])
                summary = details.get("summary", "")
                operation_id = details.get("operationId", "")
                
                # Use operationID as the endpoint ID (fallback to generated ID if not present)
                if operation_id:
                    endpoint_id = operation_id
                else:
                    endpoint_id = self._generate_endpoint_id(method, path)
                    logger.warning(f"No operationId for {method} {path}, using generated ID: {endpoint_id}")
                
                # Store lightweight index entry
                self._index[endpoint_id] = {
                    "id": endpoint_id,
                    "method": method.upper(),
                    "path": path,
                    "operation_id": operation_id,
                    "summary": summary,
                    "tags": tags
                }
                
                # Store full schema separately (keyed by endpoint_id)
                self._schemas[endpoint_id] = {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": operation_id,
                    "summary": summary,
                    "description": details.get("description", ""),
                    "tags": tags,
                    "parameters": details.get("parameters", []),
                    "requestBody": details.get("requestBody"),
                    "responses": details.get("responses", {}),
                    "security": details.get("security", []),
                    "roles": details.get("roles", [])
                }
        
        logger.info(f"Built index with {len(self._index)} endpoints")
        logger.info(f"Built schemas for {len(self._schemas)} endpoints")
        self._save_index()
        self._save_schemas()
        self._schemas_loaded = True
    
    def _generate_endpoint_id(self, method: str, path: str) -> str:
        """Generate a unique ID for an endpoint."""
        # Clean the path for use in ID
        clean_path = path.replace('/', '-').replace('{', '').replace('}', '')
        if clean_path.startswith('-'):
            clean_path = clean_path[1:]
        return f"{method.upper()}{clean_path}"
    
    def _get_summary_model(self, endpoint_id: str) -> Optional[EndpointSummary]:
        """Get or create a cached EndpointSummary model for an endpoint."""
        if endpoint_id not in self._index:
            return None
        
        if endpoint_id not in self._index_models:
            try:
                self._index_models[endpoint_id] = EndpointSummary(**self._index[endpoint_id])
            except Exception as e:
                logger.warning(f"Failed to create EndpointSummary for {endpoint_id}: {e}")
                return None
        
        return self._index_models[endpoint_id]
    
    def _get_schema_model(self, endpoint_id: str) -> Optional[EndpointSchema]:
        """Get or create a cached EndpointSchema model for an endpoint."""
        if not self._schemas_loaded:
            self._load_schemas()
        
        if endpoint_id not in self._schemas:
            return None
        
        if endpoint_id not in self._schema_models:
            try:
                self._schema_models[endpoint_id] = EndpointSchema.from_raw(self._schemas[endpoint_id])
            except Exception as e:
                logger.warning(f"Failed to create EndpointSchema for {endpoint_id}: {e}")
                return None
        
        return self._schema_models[endpoint_id]
    
    def list_endpoints_by_tag(self, tags: List[str]) -> List[EndpointSummary]:
        """
        Get endpoints that match any of the provided tags.
        
        Args:
            tags: List of tag names to filter by
            
        Returns:
            List of EndpointSummary models (type-safe)
        """
        if not tags:
            # Return all endpoints if no tags specified
            return [
                model for endpoint_id in self._index
                if (model := self._get_summary_model(endpoint_id)) is not None
            ]
        
        results: List[EndpointSummary] = []
        tags_lower = [tag.lower() for tag in tags]
        
        for endpoint_id, endpoint in self._index.items():
            endpoint_tags = [t.lower() for t in endpoint.get("tags", [])]
            
            # Check if any of the requested tags match
            if any(tag in endpoint_tags for tag in tags_lower):
                model = self._get_summary_model(endpoint_id)
                if model is not None:
                    results.append(model)
        
        logger.info(f"Found {len(results)} endpoints for tags: {tags}")
        return results
    
    def list_endpoints_by_tag_raw(self, tags: List[str]) -> List[Dict[str, Any]]:
        """
        Get endpoints that match any of the provided tags (raw dict format).
        
        Args:
            tags: List of tag names to filter by
            
        Returns:
            List of endpoint summaries as dictionaries
        """
        if not tags:
            # Return all endpoints if no tags specified
            return list(self._index.values())
        
        results = []
        tags_lower = [tag.lower() for tag in tags]
        
        for endpoint in self._index.values():
            endpoint_tags = [t.lower() for t in endpoint.get("tags", [])]
            
            # Check if any of the requested tags match
            if any(tag in endpoint_tags for tag in tags_lower):
                results.append(endpoint)
        
        logger.info(f"Found {len(results)} endpoints for tags: {tags}")
        return results
    
    def get_endpoint_schema(self, endpoint_id: str) -> Optional[EndpointSchema]:
        """
        Get the full OpenAPI schema for a specific endpoint (lazy-loaded from file).
        
        Args:
            endpoint_id: The unique identifier of the endpoint
            
        Returns:
            EndpointSchema model or None if not found
        """
        model = self._get_schema_model(endpoint_id)
        
        if model is not None:
            logger.debug(f"Found schema for {endpoint_id}")
            return model
        
        # Check if endpoint exists in index but schema is missing
        if endpoint_id in self._index:
            logger.warning(f"Schema not found for endpoint {endpoint_id} - try regenerating the index")
        else:
            logger.warning(f"Endpoint {endpoint_id} not found in index")
        
        return None
    
    def get_endpoint_schema_raw(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the full OpenAPI schema for a specific endpoint as raw dict.
        
        Args:
            endpoint_id: The unique identifier of the endpoint
            
        Returns:
            Full endpoint schema as dictionary or None if not found
        """
        # Lazy load schemas if not already loaded
        if not self._schemas_loaded:
            self._load_schemas()
        
        # Check if schema exists
        if endpoint_id in self._schemas:
            logger.debug(f"Found schema for {endpoint_id}")
            return self._schemas[endpoint_id]
        
        # Check if endpoint exists in index but schema is missing
        if endpoint_id in self._index:
            logger.warning(f"Schema not found for endpoint {endpoint_id} - try regenerating the index")
        else:
            logger.warning(f"Endpoint {endpoint_id} not found in index")
        
        return None
    
    def get_all_tags(self) -> List[str]:
        """
        Get a list of all unique tags in the index.
        
        Returns:
            Sorted list of unique tag names
        """
        tags = set()
        for endpoint in self._index.values():
            tags.update(endpoint.get("tags", []))
        return sorted(list(tags))
    
    def get_endpoint_by_id(self, endpoint_id: str) -> Optional[EndpointSummary]:
        """
        Get endpoint summary by ID.

        Args:
            endpoint_id: The unique identifier of the endpoint

        Returns:
            EndpointSummary model or None if not found
        """
        return self._get_summary_model(endpoint_id)
    
    def get_endpoint_by_id_raw(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get endpoint summary by ID as raw dict.

        Args:
            endpoint_id: The unique identifier of the endpoint

        Returns:
            Endpoint summary as dictionary or None if not found
        """
        return self._index.get(endpoint_id)

    def reload(self) -> None:
        """
        Reload the endpoint index and schemas from disk.

        This clears the in-memory cache and reloads fresh data from the JSON files.
        Useful after the index files have been regenerated.
        """
        logger.info("Reloading endpoint index from disk...")

        # Reset the schemas loaded flag so schemas will be reloaded on next access
        self._schemas_loaded = False
        self._schemas = {}
        self._schema_models = {}
        self._index_models = {}

        # Reload the index
        if self.index_file.exists():
            self._load_index()
        else:
            logger.warning(f"Index file not found during reload: {self.index_file}")
            self._index = {}

        logger.info(f"Endpoint index reloaded with {len(self._index)} endpoints")


# Global instance for easy access
_endpoint_index: Optional[EndpointIndex] = None


def get_endpoint_index() -> EndpointIndex:
    """
    Get the global endpoint index instance (lazy initialization).

    Returns:
        EndpointIndex instance
    """
    global _endpoint_index

    if _endpoint_index is None:
        _endpoint_index = EndpointIndex()

    return _endpoint_index


def reload_endpoint_index() -> None:
    """
    Reload the global endpoint index from disk.

    This should be called after the index JSON files have been regenerated
    to ensure the in-memory cache reflects the latest data.
    """
    global _endpoint_index

    if _endpoint_index is not None:
        _endpoint_index.reload()
    else:
        # If not yet initialized, the next call to get_endpoint_index() will load fresh data
        logger.info("Endpoint index not yet initialized, will load fresh on first access")
