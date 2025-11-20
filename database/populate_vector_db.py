#!/usr/bin/env python3
"""
Script to populate vector databases with OBP glossary and endpoint documentation.
Uses the vector store provider abstraction for database agnosticism.
"""

import os
import sys
import argparse
import json
import requests
from typing import List, Dict, Any
from dotenv import load_dotenv

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from langchain_core.documents import Document
from src.tools.retrieval.retriever_config import (
    VectorStoreConfig, 
    get_vector_store_manager, 
    VectorStoreError,
    ConfigurationError
)
from database.document_schemas import GlossaryDocumentSchema, EndpointDocumentSchema

# Load environment variables
load_dotenv()

def get_obp_config(endpoint_type="static"):
    """Get OBP configuration from environment variables."""
    base_url = os.getenv("OBP_BASE_URL")
    api_version = os.getenv("OBP_API_VERSION")
    chroma_dir = os.getenv("CHROMADB_DIRECTORY")

    if not all([base_url, api_version, chroma_dir]):
        raise ValueError("Missing required environment variables: OBP_BASE_URL, OBP_API_VERSION, CHROMADB_DIRECTORY")

    return {
        "base_url": base_url,
        "api_version": api_version,
        "chroma_dir": chroma_dir,
        "glossary_url": f"{base_url}/obp/{api_version}/api/glossary",
        "swagger_url": f"{base_url}/obp/{api_version}/resource-docs/{api_version}/swagger?content={endpoint_type}"
    }

def fetch_obp_data(url: str) -> Dict[str, Any]:
    """Fetch data from OBP endpoint."""
    print(f"Fetching data from: {url}")

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        raise

def process_glossary_data(glossary_data: Dict[str, Any]) -> List[Document]:
    """Process OBP glossary data into documents for vector storage with schema validation."""
    validated_documents = []
    validation_errors = 0
    
    # Debug: Print the structure to understand the data format
    print(f"Glossary data keys: {list(glossary_data.keys()) if isinstance(glossary_data, dict) else 'Not a dict'}")

    # Try different possible structures for glossary data
    glossary_items = []
    if isinstance(glossary_data, dict):
        # Try common field names including the actual one we found
        for key in ['glossary_items', 'glossary', 'items', 'data', 'results']:
            if key in glossary_data:
                glossary_items = glossary_data[key]
                break

        # If no standard key found, check if the whole response is the glossary
        if not glossary_items and all(isinstance(v, dict) and ('title' in v or 'description' in v) for v in glossary_data.values()):
            glossary_items = list(glossary_data.values())
    elif isinstance(glossary_data, list):
        glossary_items = glossary_data

    print(f"Found {len(glossary_items)} glossary items to process")

    for item in glossary_items:
        if not isinstance(item, dict):
            validation_errors += 1
            continue

        # Extract title
        title = item.get("title") or item.get("name") or item.get("term") or ""

        # Handle description which might be a string or an object with markdown/html
        description_raw = item.get("description") or item.get("definition") or item.get("desc") or ""
        description = ""

        if isinstance(description_raw, dict):
            # If description is an object, prefer markdown over html, then other text fields
            description = (description_raw.get("markdown") or 
                          description_raw.get("html") or 
                          description_raw.get("text") or 
                          description_raw.get("content") or 
                          str(description_raw))
        elif isinstance(description_raw, str):
            description = description_raw
        else:
            description = str(description_raw) if description_raw else ""

        # Clean up the description - remove excessive whitespace and newlines
        if description:
            description = description.strip()

        # Validate using schema
        try:
            # Skip items with empty title or description
            if not title or not description:
                validation_errors += 1
                continue
                
            # Create schema instance for validation
            schema = GlossaryDocumentSchema(
                title=title,
                description=description
            )
            
            # Transform to Document using schema methods
            validated_documents.append(Document(
                page_content=schema.to_document_content(),
                metadata=schema.to_metadata()
            ))
            
        except Exception as e:
            validation_errors += 1
            print(f"Validation error for glossary item '{title}': {e}")
            continue

    print(f"Created {len(validated_documents)} valid glossary documents")
    if validation_errors > 0:
        print(f"Skipped {validation_errors} invalid glossary items")
    
    return validated_documents

def process_swagger_data(swagger_data: Dict[str, Any]) -> List[Document]:
    """Process OBP swagger documentation into documents with schema validation."""
    validated_documents = []
    validation_errors = 0
    
    # Process paths (endpoints)
    paths = swagger_data.get("paths", {})
    print(f"Processing {len(paths)} API endpoints...")

    for path, methods in paths.items():
        for method, details in methods.items():
            if isinstance(details, dict):
                try:
                    # Extract key information
                    operation_id = details.get("operationId", "")
                    tags = details.get("tags", [])
                    
                    # Validate using schema
                    schema = EndpointDocumentSchema(
                        path=path,
                        method=method,
                        operation_id=operation_id,
                        details=details,
                        tags=tags
                    )
                    
                    # Transform to Document using schema methods
                    validated_documents.append(Document(
                        page_content=schema.to_document_content(),
                        metadata=schema.to_metadata()
                    ))
                    
                except Exception as e:
                    validation_errors += 1
                    print(f"Validation error for endpoint {method.upper()} {path}: {e}")
                    continue

    print(f"Created {len(validated_documents)} valid endpoint documents")
    if validation_errors > 0:
        print(f"Skipped {validation_errors} invalid endpoint definitions")
        
    return validated_documents

def validate_document_collection(documents: List[Document], collection_name: str) -> bool:
    """
    Validate an entire collection of documents against schema requirements.
    
    Args:
        documents: List of documents to validate
        collection_name: Name of the collection for logging
        
    Returns:
        bool: True if all documents are valid
    """
    if not documents:
        print(f"No documents to validate for {collection_name}")
        return False
    
    print(f"Validating {len(documents)} documents for {collection_name}...")
    
    schema_class = None
    if collection_name == "obp_glossary":
        schema_class = GlossaryDocumentSchema
    elif collection_name == "obp_endpoints":
        schema_class = EndpointDocumentSchema
    else:
        print(f"Unknown collection type: {collection_name}")
        return False
    
    valid_count = 0
    errors = []
    
    for i, doc in enumerate(documents):
        try:
            # Try to reconstruct schema from document to validate format
            schema_instance = schema_class.from_document(doc.page_content, doc.metadata)
            
            # Verify we can convert it back
            test_content = schema_instance.to_document_content()
            test_metadata = schema_instance.to_metadata()
            
            if not test_content or not test_metadata:
                errors.append(f"Document {i} produced empty content or metadata")
                continue
                
            valid_count += 1
            
        except Exception as e:
            errors.append(f"Document {i} validation error: {e}")
    
    # Report validation results
    if valid_count == len(documents):
        print(f"✓ All {valid_count} documents in {collection_name} are valid")
        return True
    else:
        print(f"✗ Only {valid_count}/{len(documents)} documents in {collection_name} are valid")
        if errors:
            print(f"First few errors:")
            for e in errors[:3]:  # Show only first few errors
                print(f"  - {e}")
            if len(errors) > 3:
                print(f"  ... and {len(errors) - 3} more errors")
        return False

def populate_collection(documents: List[Document], collection_name: str, chroma_dir: str = None):
    """
    Populate a vector database collection using the provider abstraction with schema validation.
    
    Args:
        documents: List of documents to add to the collection
        collection_name: Name of the collection
        chroma_dir: Legacy parameter (optional, kept for compatibility)
    """
    if not documents:
        print(f"No documents to add to {collection_name}")
        return

    try:
        # Validate documents against schema
        if not validate_document_collection(documents, collection_name):
            print(f"WARNING: Some documents for {collection_name} failed validation")
            proceed = input("Do you want to proceed with insertion anyway? (y/n): ").lower()
            if proceed != 'y':
                print(f"Aborting population of {collection_name}")
                return
            print(f"Proceeding with insertion despite validation errors")
        
        print(f"Setting up vector store for collection: {collection_name}")
        
        # Get the vector store manager using the configured provider
        manager = get_vector_store_manager()
        
        # Create configuration with overwrite_existing=True to replace existing collection
        config = VectorStoreConfig(
            collection_name=collection_name,
            embedding_model="text-embedding-3-large",
            overwrite_existing=True  # Important: We want to replace existing collections
        )
        
        print(f"Getting vector store provider for collection: {collection_name}")
        # Get the provider from the manager to use lower-level operations
        provider = manager._vector_store_provider
        
        # Check if collection exists
        existing_collections = provider.get_all_collection_names()
        if collection_name in existing_collections:
            print(f"Collection {collection_name} already exists, it will be replaced")
        
        # Create a new vector store with overwrite permission
        print(f"Creating vector store for collection: {collection_name}")
        vector_store = provider.create_vector_store(config)
        
        print(f"Adding {len(documents)} documents to {collection_name}...")
        
        # Add documents in batches to avoid memory issues
        batch_size = 100
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            vector_store.add_documents(batch)
            print(f"Added batch {i//batch_size + 1}/{(len(documents) + batch_size - 1)//batch_size}")
        
        print(f"Successfully populated {collection_name} with {len(documents)} documents")
        
        # Verify document schemas in the vector store
        if hasattr(provider, 'validate_document_schemas'):
            try:
                schema_valid = provider.validate_document_schemas(vector_store, collection_name)
                if schema_valid:
                    print(f"✓ Document schemas in {collection_name} validated successfully")
                else:
                    print(f"✗ Document schemas in {collection_name} validation failed")
            except NotImplementedError:
                print(f"Schema validation not supported by the current provider")
        
        # Clear cache to ensure fresh data on next retrieval
        manager.clear_cache()
        
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except VectorStoreError as e:
        print(f"Vector store error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

def main():
    """Main function to populate vector database collections."""
    print("Starting vector database population script...")
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Populate vector databases with OBP glossary and endpoint documentation.")
    parser.add_argument(
        "--endpoints",
        choices=["static", "dynamic", "all"],
        default="static",
        help="Type of endpoints to load: static (default), dynamic, or all (static + dynamic)"
    )
    args = parser.parse_args()

    try:
        # Get configuration
        config = get_obp_config(args.endpoints)

        # Fetch data from OBP endpoints
        print("\n" + "="*50)
        print("FETCHING OBP DATA")
        print("="*50)

        glossary_data = fetch_obp_data(config["glossary_url"])
        swagger_data = fetch_obp_data(config["swagger_url"])

        # Process data into documents
        print("\n" + "="*50)
        print("PROCESSING DATA")
        print("="*50)

        glossary_documents = process_glossary_data(glossary_data)
        endpoint_documents = process_swagger_data(swagger_data)

        # Populate collections
        print("\n" + "="*50)
        print("POPULATING VECTOR DATABASE")
        print("="*50)

        # Now using the database-agnostic population method
        populate_collection(glossary_documents, "obp_glossary")
        populate_collection(endpoint_documents, "obp_endpoints")

        print("\n" + "="*50)
        print("POPULATION COMPLETE")
        print("="*50)
        print(f"Glossary items: {len(glossary_documents)}")
        print(f"Endpoint documents: {len(endpoint_documents)}")
        print(f"Total documents: {len(glossary_documents) + len(endpoint_documents)}")

    except Exception as e:
        print(f"Error during population: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()