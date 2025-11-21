"""
Centralised config for database-related settings.
"""
from pathlib import Path

# Database directory relative to this file
DATABASE_DIR = Path(__file__).parent.resolve()

# ChromaDB directory
CHROMADB_DIRECTORY = DATABASE_DIR / "data"

# Ensure the ChromaDB directory exists
CHROMADB_DIRECTORY.mkdir(parents=True, exist_ok=True)

def get_chromadb_directory() -> str:
    """Get the ChromaDB directory path as a string."""
    return str(CHROMADB_DIRECTORY)