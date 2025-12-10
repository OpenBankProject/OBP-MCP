#!/usr/bin/env python3
"""
Script to generate the lightweight endpoint index from OBP swagger data.

This script fetches the swagger/OpenAPI specification from the OBP API
and generates a lightweight index for fast endpoint discovery.
"""
import os
import sys
import argparse
from pathlib import Path

# Add src and database to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tools.endpoint_index import EndpointIndex
from database.populate_vector_db import get_obp_config, fetch_obp_data


def main():
    """Main function to generate endpoint index."""
    print("Starting endpoint index generation...")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate lightweight endpoint index from OBP swagger data."
    )
    parser.add_argument(
        "--endpoints",
        choices=["static", "dynamic", "all"],
        default="static",
        help="Type of endpoints to index: static (default), dynamic, or all"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file path for the index (default: database/endpoint_index.json)"
    )
    args = parser.parse_args()
    
    try:
        # Get configuration (reuses existing function from populate_vector_db)
        config = get_obp_config(args.endpoints)
        
        # Fetch swagger data (reuses existing function from populate_vector_db)
        print("\n" + "="*50)
        print("FETCHING SWAGGER DATA")
        print("="*50)
        swagger_data = fetch_obp_data(config["swagger_url"])
        
        # Build index
        print("\n" + "="*50)
        print("BUILDING ENDPOINT INDEX")
        print("="*50)
        
        index = EndpointIndex(index_file=args.output)
        index.build_index_from_swagger(swagger_data)
        
        # Print statistics
        print("\n" + "="*50)
        print("INDEX GENERATION COMPLETE")
        print("="*50)
        print(f"Total endpoints indexed: {len(index._index)}")
        print(f"Total unique tags: {len(index.get_all_tags())}")
        print(f"Output file: {index.index_file}")
        
        # Print sample of tags
        all_tags = index.get_all_tags()
        if all_tags:
            print(f"\nSample tags (first 10):")
            for tag in all_tags[:10]:
                print(f"  - {tag}")
        
    except Exception as e:
        print(f"Error during index generation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
