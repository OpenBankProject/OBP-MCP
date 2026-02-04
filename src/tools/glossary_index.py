"""
Glossary Index Management for OBP Glossary Terms.

This module provides lightweight glossary term indexing for quick lookup and discovery.
Each glossary term contains a title and description (markdown and/or HTML).
"""
import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class GlossaryIndex:
    """
    Manages a lightweight index of OBP glossary terms.
    
    Index entries contain term information (id, title, description with markdown/html).
    """
    
    def __init__(self, index_file: Optional[str] = None):
        """
        Initialize the glossary index.
        
        Args:
            index_file: Path to the index JSON file. If None, uses default location.
        """
        if index_file is None:
            index_file = os.path.join(
                os.path.dirname(__file__), 
                "../../database/glossary_index.json"
            )
        
        self.index_file = Path(index_file).resolve()
        self._index: Dict[str, Dict[str, Any]] = {}
        
        # Load index if it exists
        if self.index_file.exists():
            self._load_index()
    
    def _load_index(self) -> None:
        """Load the glossary index from disk."""
        try:
            with open(self.index_file, 'r') as f:
                data = json.load(f)
                self._index = data.get('glossary_terms', {})
                logger.info(f"Loaded {len(self._index)} glossary terms from index")
        except Exception as e:
            logger.error(f"Failed to load glossary index: {e}")
            self._index = {}
    
    def _save_index(self) -> None:
        """Save the glossary index to disk."""
        try:
            # Ensure directory exists
            self.index_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.index_file, 'w') as f:
                json.dump({'glossary_terms': self._index}, f, indent=2)
            logger.info(f"Saved {len(self._index)} glossary terms to index")
        except Exception as e:
            logger.error(f"Failed to save glossary index: {e}")
    
    def add_term(self, term_id: str, title: str, description: Dict[str, str]) -> None:
        """
        Add or update a glossary term in the index.
        
        Args:
            term_id: Unique identifier for the term (derived from title)
            title: The glossary term title
            description: Dictionary with 'markdown' and/or 'html' keys
        """
        self._index[term_id] = {
            "id": term_id,
            "title": title,
            "description": description
        }
    
    def get_term(self, term_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific glossary term by ID.
        
        Args:
            term_id: The unique identifier of the term
            
        Returns:
            Dictionary containing term details or None if not found
        """
        return self._index.get(term_id)
    
    def list_all_terms(self) -> List[Dict[str, Any]]:
        """
        Get all glossary terms.
        
        Returns:
            List of all glossary terms with id, title, and description
        """
        return list(self._index.values())
    
    def search_terms(self, query: str) -> List[Dict[str, Any]]:
        """
        Search for glossary terms by title or description content.
        
        Args:
            query: Search query string (case-insensitive)
            
        Returns:
            List of matching glossary terms
        """
        query_lower = query.lower()
        results = []
        
        for term in self._index.values():
            # Search in title
            if query_lower in term['title'].lower():
                results.append(term)
                continue
            
            # Search in description markdown
            desc = term.get('description', {})
            markdown = desc.get('markdown', '')
            html = desc.get('html', '')
            
            if query_lower in markdown.lower() or query_lower in html.lower():
                results.append(term)
        
        return results
    
    def get_terms_by_prefix(self, prefix: str) -> List[Dict[str, Any]]:
        """
        Get glossary terms whose titles start with a specific prefix.
        
        Args:
            prefix: The prefix to match (case-insensitive)
            
        Returns:
            List of matching glossary terms
        """
        prefix_lower = prefix.lower()
        results = []
        
        for term in self._index.values():
            if term['title'].lower().startswith(prefix_lower):
                results.append(term)
        
        return sorted(results, key=lambda x: x['title'])
    
    def save(self) -> None:
        """Save the index to disk."""
        self._save_index()
    
    def get_all_term_ids(self) -> List[str]:
        """
        Get all term IDs.
        
        Returns:
            List of all term IDs
        """
        return list(self._index.keys())
    
    def __len__(self) -> int:
        """Return the number of terms in the index."""
        return len(self._index)

    def reload(self) -> None:
        """
        Reload the glossary index from disk.

        This clears the in-memory cache and reloads fresh data from the JSON file.
        Useful after the index file has been regenerated.
        """
        logger.info("Reloading glossary index from disk...")

        # Reload the index
        if self.index_file.exists():
            self._load_index()
        else:
            logger.warning(f"Index file not found during reload: {self.index_file}")
            self._index = {}

        logger.info(f"Glossary index reloaded with {len(self._index)} terms")


# Global instance for easy access
_glossary_index: Optional[GlossaryIndex] = None


def get_glossary_index() -> GlossaryIndex:
    """
    Get or create the global glossary index instance.

    Returns:
        The global GlossaryIndex instance
    """
    global _glossary_index
    if _glossary_index is None:
        _glossary_index = GlossaryIndex()
    return _glossary_index


def reload_glossary_index() -> None:
    """
    Reload the global glossary index from disk.

    This should be called after the index JSON file has been regenerated
    to ensure the in-memory cache reflects the latest data.
    """
    global _glossary_index

    if _glossary_index is not None:
        _glossary_index.reload()
    else:
        # If not yet initialized, the next call to get_glossary_index() will load fresh data
        logger.info("Glossary index not yet initialized, will load fresh on first access")
