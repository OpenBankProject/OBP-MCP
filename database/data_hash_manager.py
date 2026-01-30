"""
Module to manage OBP data hashing and comparison for automatic database updates.

This module provides functionality to:
- Fetch OBP data (glossary and endpoints)
- Compute content hashes
- Compare with previously stored hashes
- Trigger database updates when changes are detected
"""

import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import requests

logger = logging.getLogger(__name__)


class DataHashManager:
    """Manages hashing and comparison of OBP data for change detection."""
    
    def __init__(self, hash_storage_path: Optional[str] = None):
        """
        Initialize the DataHashManager.
        
        Args:
            hash_storage_path: Path to store hash data. Defaults to .obp_data_hashes.json
                              in the project root.
        """
        if hash_storage_path is None:
            hash_storage_path = ".obp_data_hashes.json"
        
        self.hash_storage_path = Path(hash_storage_path)
        self.base_url = os.getenv("OBP_BASE_URL")
        self.api_version = os.getenv("OBP_API_VERSION")
        
        if not self.base_url or not self.api_version:
            raise ValueError("OBP_BASE_URL and OBP_API_VERSION must be set in environment")
    
    def check_obp_health(self) -> bool:
        """
        Check if OBP API is up and responding.

        Returns:
            True if OBP is healthy, False otherwise
        """
        root_url = f"{self.base_url}/obp/{self.api_version}/root"
        try:
            response = requests.get(root_url, timeout=10)
            response.raise_for_status()
            logger.debug(f"OBP health check passed: {root_url}")
            return True
        except requests.exceptions.HTTPError as e:
            logger.warning(f"OBP health check failed ({root_url}): {e}")
            logger.warning(f"OBP response body: {response.text}")
            return False
        except requests.exceptions.RequestException as e:
            logger.warning(f"OBP health check failed ({root_url}): {e}")
            return False

    def _fetch_obp_data(self, url: str) -> Dict[str, Any]:
        """
        Fetch data from OBP endpoint.

        Args:
            url: The endpoint URL to fetch from

        Returns:
            JSON response data

        Raises:
            requests.RequestException: If the request fails
        """
        logger.info(f"Fetching OBP data from: {url}")
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            # Log the response body to see what OBP is telling us
            try:
                error_body = response.text
                logger.error(f"HTTP error from {url}: {e}")
                logger.error(f"OBP response body: {error_body}")
            except Exception:
                logger.error(f"HTTP error from {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching data from {url}: {e}")
            raise
    
    def _compute_hash(self, data: Any) -> str:
        """
        Compute SHA-256 hash of data.
        
        Args:
            data: Data to hash (will be JSON serialized)
            
        Returns:
            Hexadecimal hash string
        """
        # Convert to JSON string with sorted keys for consistent hashing
        json_str = json.dumps(data, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(json_str.encode('utf-8')).hexdigest()
    
    def fetch_current_data_hashes(self, endpoint_type: str = "all") -> Dict[str, str]:
        """
        Fetch current OBP data and compute hashes.
        
        Args:
            endpoint_type: Type of endpoints to include ("static", "dynamic", or "all")
            
        Returns:
            Dictionary with 'glossary' and 'endpoints' hashes
        """
        glossary_url = f"{self.base_url}/obp/{self.api_version}/api/glossary"
        swagger_url = f"{self.base_url}/obp/{self.api_version}/resource-docs/{self.api_version}/swagger?content={endpoint_type}"
        
        try:
            # Fetch data
            glossary_data = self._fetch_obp_data(glossary_url)
            swagger_data = self._fetch_obp_data(swagger_url)
            
            # Compute hashes
            hashes = {
                "glossary": self._compute_hash(glossary_data),
                "endpoints": self._compute_hash(swagger_data),
                "endpoint_type": endpoint_type
            }
            
            logger.info(f"Computed hashes - Glossary: {hashes['glossary'][:8]}..., "
                       f"Endpoints: {hashes['endpoints'][:8]}...")
            
            return hashes
            
        except Exception as e:
            logger.error(f"Error fetching current data hashes: {e}")
            raise
    
    def load_stored_hashes(self) -> Optional[Dict[str, str]]:
        """
        Load previously stored hashes from disk.
        
        Returns:
            Dictionary of stored hashes, or None if file doesn't exist
        """
        if not self.hash_storage_path.exists():
            logger.info(f"No stored hashes found at {self.hash_storage_path}")
            return None
        
        try:
            with open(self.hash_storage_path, 'r') as f:
                hashes = json.load(f)
            logger.info(f"Loaded stored hashes from {self.hash_storage_path}")
            return hashes
        except Exception as e:
            logger.error(f"Error loading stored hashes: {e}")
            return None
    
    def save_hashes(self, hashes: Dict[str, str]) -> None:
        """
        Save hashes to disk.
        
        Args:
            hashes: Dictionary of hashes to save
        """
        try:
            # Ensure directory exists
            self.hash_storage_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.hash_storage_path, 'w') as f:
                json.dump(hashes, f, indent=2)
            
            logger.info(f"Saved hashes to {self.hash_storage_path}")
        except Exception as e:
            logger.error(f"Error saving hashes: {e}")
            raise
    
    def compare_hashes(
        self, 
        current_hashes: Dict[str, str], 
        stored_hashes: Optional[Dict[str, str]]
    ) -> Tuple[bool, Dict[str, bool]]:
        """
        Compare current hashes with stored hashes.
        
        Args:
            current_hashes: Current data hashes
            stored_hashes: Previously stored hashes (or None)
            
        Returns:
            Tuple of (needs_update, changes_dict) where:
            - needs_update: True if any changes detected
            - changes_dict: Dictionary indicating which collections changed
        """
        if stored_hashes is None:
            logger.info("No stored hashes - database needs initial population")
            return True, {"glossary": True, "endpoints": True}
        
        changes = {
            "glossary": current_hashes.get("glossary") != stored_hashes.get("glossary"),
            "endpoints": current_hashes.get("endpoints") != stored_hashes.get("endpoints")
        }
        
        needs_update = any(changes.values())
        
        if needs_update:
            changed_items = [k for k, v in changes.items() if v]
            logger.info(f"Changes detected in: {', '.join(changed_items)}")
        else:
            logger.info("No changes detected - database is up to date")
        
        return needs_update, changes
    
    def check_for_updates(self, endpoint_type: str = "all") -> Tuple[bool, Dict[str, bool]]:
        """
        Check if OBP data has changed since last import.

        Args:
            endpoint_type: Type of endpoints to check ("static", "dynamic", or "all")

        Returns:
            Tuple of (needs_update, changes_dict)

        Raises:
            ConnectionError: If OBP API is not available
        """
        # First check if OBP is up
        if not self.check_obp_health():
            raise ConnectionError("OBP API is not available - skipping update check")

        current_hashes = self.fetch_current_data_hashes(endpoint_type)
        stored_hashes = self.load_stored_hashes()

        return self.compare_hashes(current_hashes, stored_hashes)
    
    def update_stored_hashes(self, endpoint_type: str = "all") -> None:
        """
        Fetch current data and update stored hashes.
        
        Args:
            endpoint_type: Type of endpoints to include
        """
        current_hashes = self.fetch_current_data_hashes(endpoint_type)
        self.save_hashes(current_hashes)
        logger.info("Stored hashes updated successfully")
