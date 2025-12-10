"""
Endpoint Index Management for Hybrid Tag-Based Routing.

This module provides lightweight endpoint indexing and lazy schema loading
following the hybrid approach for cost-effective API endpoint discovery.
"""
import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class EndpointIndex:
    """
    Manages a lightweight index of API endpoints with lazy schema loading.
    
    Index entries contain minimal information (id, name, method, path, summary, tags)
    while full schemas are loaded on-demand to minimize token usage.
    """
    
    def __init__(self, index_file: Optional[str] = None):
        """
        Initialize the endpoint index.
        
        Args:
            index_file: Path to the index JSON file. If None, uses default location.
        """
        if index_file is None:
            index_file = os.path.join(
                os.path.dirname(__file__), 
                "../../database/endpoint_index.json"
            )
        
        self.index_file = Path(index_file).resolve()
        self._index: Dict[str, Dict[str, Any]] = {}
        self._schemas: Dict[str, Dict[str, Any]] = {}  # Lazy-loaded schemas
        
        # Load index if it exists
        if self.index_file.exists():
            self._load_index()
    
    def _load_index(self) -> None:
        """Load the endpoint index from disk."""
        try:
            with open(self.index_file, 'r') as f:
                data = json.load(f)
                self._index = data.get('endpoints', {})
                logger.info(f"Loaded {len(self._index)} endpoints from index")
        except Exception as e:
            logger.error(f"Failed to load endpoint index: {e}")
            self._index = {}
    
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
    
    def build_index_from_swagger(self, swagger_data: Dict[str, Any]) -> None:
        """
        Build the lightweight endpoint index from swagger/OpenAPI data.
        
        Args:
            swagger_data: Swagger/OpenAPI specification as a dictionary
        """
        self._index = {}
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
        
        logger.info(f"Built index with {len(self._index)} endpoints")
        self._save_index()
    
    def _generate_endpoint_id(self, method: str, path: str) -> str:
        """Generate a unique ID for an endpoint."""
        # Clean the path for use in ID
        clean_path = path.replace('/', '-').replace('{', '').replace('}', '')
        if clean_path.startswith('-'):
            clean_path = clean_path[1:]
        return f"{method.upper()}{clean_path}"
    
    def list_endpoints_by_tag(self, tags: List[str]) -> List[Dict[str, Any]]:
        """
        Get endpoints that match any of the provided tags.
        
        Args:
            tags: List of tag names to filter by
            
        Returns:
            List of endpoint summaries (no full schemas)
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
    
    def get_endpoint_schema(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get the full OpenAPI schema for a specific endpoint (lazy-loaded).
        
        Args:
            endpoint_id: The unique identifier of the endpoint
            
        Returns:
            Full endpoint schema or None if not found
        """
        # Check if schema is already cached
        if endpoint_id in self._schemas:
            logger.debug(f"Using cached schema for {endpoint_id}")
            return self._schemas[endpoint_id]
        
        # Check if endpoint exists in index
        if endpoint_id not in self._index:
            logger.warning(f"Endpoint {endpoint_id} not found in index")
            return None
        
        # Load the full schema from swagger data
        # This would typically be loaded from a separate file or API
        # For now, we'll need to fetch it from the OBP API
        try:
            endpoint = self._index[endpoint_id]
            schema = self._load_schema_from_api(endpoint["method"], endpoint["path"])
            
            if schema:
                # Cache the schema
                self._schemas[endpoint_id] = schema
                logger.info(f"Loaded and cached schema for {endpoint_id}")
            
            return schema
        except Exception as e:
            logger.error(f"Failed to load schema for {endpoint_id}: {e}")
            return None
    
    def _load_schema_from_api(self, method: str, path: str) -> Optional[Dict[str, Any]]:
        """
        Load full schema from OBP API swagger endpoint.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path
            
        Returns:
            Full endpoint schema or None
        """
        # Get OBP configuration
        base_url = os.getenv("OBP_BASE_URL")
        api_version = os.getenv("OBP_API_VERSION")
        
        if not base_url or not api_version:
            logger.warning("OBP_BASE_URL and OBP_API_VERSION must be set")
            return None
        
        try:
            # Fetch the full swagger spec
            swagger_url = f"{base_url}/obp/{api_version}/resource-docs/{api_version}/swagger?content=static"
            response = requests.get(swagger_url, timeout=30)
            response.raise_for_status()
            
            swagger_data = response.json()
            paths = swagger_data.get("paths", {})
            
            # Extract the specific endpoint
            if path in paths and method.lower() in paths[path]:
                return {path: {method.lower(): paths[path][method.lower()]}}
            
            logger.warning(f"Schema not found for {method} {path}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to fetch schema from API: {e}")
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
    
    def get_endpoint_by_id(self, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """
        Get endpoint summary by ID.
        
        Args:
            endpoint_id: The unique identifier of the endpoint
            
        Returns:
            Endpoint summary or None if not found
        """
        return self._index.get(endpoint_id)


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
