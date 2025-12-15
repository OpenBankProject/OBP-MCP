#!/usr/bin/env python3
"""
Script to generate the glossary index from OBP glossary API.

This script fetches the glossary data from the OBP API and generates
an index for fast glossary term lookup.
"""
import os
import sys
import argparse
from pathlib import Path

# Add src and database to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tools.glossary_index import GlossaryIndex
from database.populate_vector_db import get_obp_config, fetch_obp_data


def normalize_term_id(title: str) -> str:
    """
    Convert a glossary term title to a normalized ID.
    
    Args:
        title: The term title (e.g., "Account.account_id")
        
    Returns:
        Normalized ID (e.g., "account-account_id")
    """
    # Convert to lowercase and replace spaces and dots with hyphens
    term_id = title.lower()
    term_id = term_id.replace(".", "-")
    term_id = term_id.replace(" ", "-")
    term_id = term_id.replace("_", "-")
    # Remove any non-alphanumeric characters except hyphens
    term_id = ''.join(c for c in term_id if c.isalnum() or c == '-')
    # Remove consecutive hyphens
    while '--' in term_id:
        term_id = term_id.replace('--', '-')
    # Remove leading/trailing hyphens
    term_id = term_id.strip('-')
    return term_id


def main():
    """Main function to generate glossary index."""
    print("Starting glossary index generation...")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate glossary index from OBP glossary API."
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path for the index (default: database/glossary_index.json)"
    )
    args = parser.parse_args()
    
    try:
        # Get configuration
        config = get_obp_config()
        
        # Fetch glossary data
        print("\n" + "="*50)
        print("FETCHING GLOSSARY DATA")
        print("="*50)
        print(f"URL: {config['glossary_url']}")
        glossary_data = fetch_obp_data(config["glossary_url"])
        
        # Build index
        print("\n" + "="*50)
        print("BUILDING GLOSSARY INDEX")
        print("="*50)
        
        index = GlossaryIndex(index_file=args.output)
        
        # Process glossary data
        glossary_items = []
        if isinstance(glossary_data, dict):
            # Try common field names
            for key in ['glossary_items', 'glossary', 'items', 'data', 'results']:
                if key in glossary_data:
                    glossary_items = glossary_data[key]
                    break
            
            # If no standard key found, check if the whole response is the glossary
            if not glossary_items and all(
                isinstance(v, dict) and ('title' in v or 'description' in v) 
                for v in glossary_data.values()
            ):
                glossary_items = list(glossary_data.values())
        elif isinstance(glossary_data, list):
            glossary_items = glossary_data
        
        print(f"Found {len(glossary_items)} glossary items to process")
        
        # Add terms to index
        processed_count = 0
        skipped_count = 0
        
        for item in glossary_items:
            if not isinstance(item, dict):
                skipped_count += 1
                continue
            
            # Extract title
            title = item.get("title") or item.get("name") or item.get("term") or ""
            if not title:
                skipped_count += 1
                continue
            
            # Handle description which might be a string or an object
            description_raw = item.get("description") or item.get("definition") or item.get("desc") or {}
            
            # Structure the description
            if isinstance(description_raw, dict):
                description = {
                    "markdown": description_raw.get("markdown", "").strip(),
                    "html": description_raw.get("html", "").strip()
                }
            elif isinstance(description_raw, str):
                description = {
                    "markdown": description_raw.strip(),
                    "html": ""
                }
            else:
                description = {
                    "markdown": str(description_raw).strip() if description_raw else "",
                    "html": ""
                }
            
            # Skip if no description content
            if not description["markdown"] and not description["html"]:
                skipped_count += 1
                continue
            
            # Generate term ID
            term_id = normalize_term_id(title)
            
            # Add to index
            index.add_term(term_id, title, description)
            processed_count += 1
        
        # Save index
        index.save()
        
        # Print statistics
        print("\n" + "="*50)
        print("INDEX GENERATION COMPLETE")
        print("="*50)
        print(f"Total terms indexed: {processed_count}")
        print(f"Terms skipped: {skipped_count}")
        print(f"Output file: {index.index_file}")
        
        # Print sample terms
        all_terms = index.list_all_terms()
        if all_terms:
            print(f"\nSample terms (first 10):")
            for term in all_terms[:10]:
                print(f"  - {term['title']} (id: {term['id']})")
        
    except Exception as e:
        print(f"Error during index generation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
