"""
Module to handle database updates on application startup.

This module checks for OBP data changes and updates the vector database
if changes are detected.
"""

import os
import sys
import logging
import subprocess
from typing import Optional
from pathlib import Path

from .data_hash_manager import DataHashManager

logger = logging.getLogger(__name__)


class IndexStartupUpdater:
    """Manages database updates during application startup."""
    
    def __init__(self, endpoint_type: Optional[str] = None):
        """
        Initialize the DatabaseStartupUpdater.
        
        Args:
            endpoint_type: Type of endpoints to include ("static", "dynamic", or "all").
                          Defaults to value from UPDATE_DATABASE_ENDPOINT_TYPE env var,
                          or "all" if not set.
        """
        self.hash_manager = DataHashManager()
        self.endpoint_type = endpoint_type or os.getenv("UPDATE_INDEX_ENDPOINT_TYPE", "all")
        
        if self.endpoint_type not in ["static", "dynamic", "all"]:
            logger.warning(f"Invalid endpoint_type '{self.endpoint_type}', defaulting to 'all'")
            self.endpoint_type = "all"
    
    def should_update_on_startup(self) -> bool:
        """
        Check if database updates on startup are enabled.
        
        Returns:
            True if UPDATE_DATABASE_ON_STARTUP is set to 'true' (case-insensitive)
        """
        flag = os.getenv("UPDATE_INDEX_ON_STARTUP", "false").lower()
        return flag in ["true", "1", "yes", "on"]
    
    def run_populate_scripts(self) -> bool:
        """
        Run the populate_vector_db.py script.
        
        Returns:
            True if successful, False otherwise
        """
        try:
           if self._update_glossary_index() and self._update_endpoint_index():
               return True
           else:
               return False
                
        except subprocess.TimeoutExpired:
            logger.error("Index creation timed out after 5 minutes")
            return False
        except Exception as e:
            logger.error(f"Error running index creation scripts script: {e}", exc_info=True)
            return False
        
    def _update_glossary_index(self) -> bool:
        """
        Update the glossary index in the database.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get the project root and script path
            project_root = Path(__file__).parent.parent
            glossary_script_path = project_root / "scripts" / "generate_glossary_index.py"
            
            if not glossary_script_path.exists():
                logger.error(f"Glossary index script not found at {glossary_script_path}")
                return False
            
            logger.info("Running glossary index generation script")
            
            # Run the script from the project root
            cmd = [sys.executable, str(glossary_script_path)]
            
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("Glossary index creation completed successfully")
                logger.debug(f"Script output: {result.stdout}")
                return True
            else:
                logger.error(f"Glossary index creation failed with exit code {result.returncode}")
                logger.error(f"Script error output: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Glossary index creation timed out after 5 minutes")
            return False
        except Exception as e:
            logger.error(f"Error running glossary index creation script: {e}", exc_info=True)
            return False
    
    def _update_endpoint_index(self) -> bool:
        """
        Update the endpoint index in the database.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get the project root and script path
            project_root = Path(__file__).parent.parent
            endpoint_script_path = project_root / "scripts" / "generate_endpoint_index.py"
            
            if not endpoint_script_path.exists():
                logger.error(f"Endpoint index script not found at {endpoint_script_path}")
                return False
            
            logger.info(f"Running endpoint index generation script with endpoint_type: {self.endpoint_type}")
            
            # Run the script from the project root
            cmd = [sys.executable, str(endpoint_script_path), "--endpoints", self.endpoint_type]
            
            result = subprocess.run(
                cmd,
                cwd=str(project_root),
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("Endpoint index creation completed successfully")
                logger.debug(f"Script output: {result.stdout}")
                return True
            else:
                logger.error(f"Endpoint index creation failed with exit code {result.returncode}")
                logger.error(f"Script error output: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            logger.error("Endpoint index creation timed out after 5 minutes")
            return False
        except Exception as e:
            logger.error(f"Error running endpoint index creation script: {e}", exc_info=True)
            return False
    
    def check_and_update(self) -> bool:
        """
        Check for data changes and update index if needed.
        
        Returns:
            True if update was performed successfully, False otherwise.
            Returns True if no update was needed.
        """
        if not self.should_update_on_startup():
            logger.info("Index update on startup is disabled (UPDATE_INDEX_ON_STARTUP=false)")
            return True
        
        logger.info("Checking for OBP data changes...")
        
        try:
            # Check if data has changed
            needs_update, changes = self.hash_manager.check_for_updates(self.endpoint_type)
            
            if not needs_update:
                logger.info("✓ Index is up to date - no update needed")
                return True
            
            # Log what changed
            changed_collections = [k for k, v in changes.items() if v]
            logger.info(f"⚠ Changes detected in: {', '.join(changed_collections)}")
            logger.info("Starting index update...")
            
            # Run the populate script
            success = self.run_populate_scripts()
            
            if success:
                # Update stored hashes
                self.hash_manager.update_stored_hashes(self.endpoint_type)
                logger.info("✓ Database update completed and hashes updated")
                return True
            else:
                logger.error("✗ Database update failed")
                return False
                
        except Exception as e:
            logger.error(f"Error during index update check: {e}", exc_info=True)
            return False


async def update_index_on_startup(endpoint_type: Optional[str] = None) -> bool:
    """
    Async wrapper for database update on startup.
    
    Args:
        endpoint_type: Type of endpoints to include ("static", "dynamic", or "all")
        
    Returns:
        True if update was successful or not needed, False if update failed
    """
    updater = IndexStartupUpdater(endpoint_type)
    return updater.check_and_update()
