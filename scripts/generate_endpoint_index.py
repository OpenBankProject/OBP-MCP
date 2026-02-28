#!/usr/bin/env python3
"""
Script to generate the lightweight endpoint index from OBP resource docs.

This script fetches the resource docs from the OBP API and generates a 
lightweight index for fast endpoint discovery. Resource docs provide richer
information than swagger, including roles/entitlements required for each endpoint.
"""
import os
import sys
import argparse
from pathlib import Path

# Add src and database to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.tools.endpoint_index import EndpointIndex
from database.obp_utils import get_obp_config, fetch_obp_data


def main():
    """Main function to generate endpoint index."""
    print("Starting endpoint index generation...")
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Generate lightweight endpoint index from OBP resource docs."
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
    parser.add_argument(
        "--use-swagger",
        action="store_true",
        help="Use swagger endpoint instead of resource docs (not recommended - lacks role info)"
    )
    args = parser.parse_args()
    
    use_resource_docs = not args.use_swagger
    
    try:
        # Get configuration
        config = get_obp_config(args.endpoints, use_resource_docs=use_resource_docs)
        
        # Fetch data
        print("\n" + "="*50)
        print(f"FETCHING {'RESOURCE DOCS' if use_resource_docs else 'SWAGGER'} DATA")
        print("="*50)
        print(f"URL: {config['data_url']}")
        
        data = fetch_obp_data(config["data_url"])
        
        # Build index
        print("\n" + "="*50)
        print("BUILDING ENDPOINT INDEX")
        print("="*50)
        
        index = EndpointIndex(index_file=args.output)
        
        if use_resource_docs:
            index.build_index_from_resource_docs(data)
        else:
            index.build_index_from_swagger(data)
        
        # Print statistics
        print("\n" + "="*50)
        print("INDEX GENERATION COMPLETE")
        print("="*50)
        print(f"Data source: {'Resource Docs' if use_resource_docs else 'Swagger'}")
        print(f"Total endpoints indexed: {len(index._index)}")
        print(f"Total unique tags: {len(index.get_all_tags())}")
        print(f"Index file: {index.index_file}")
        print(f"Schemas file: {index.schemas_file}")
        
        # Print sample of tags
        all_tags = index.get_all_tags()
        if all_tags:
            print(f"\nSample tags (first 10):")
            for tag in all_tags[:10]:
                print(f"  - {tag}")
        
        # If using resource docs, show role statistics
        if use_resource_docs:
            endpoints_with_roles = sum(
                1 for schema in index._schemas.values() 
                if schema.get("roles")
            )
            print(f"\nEndpoints with role requirements: {endpoints_with_roles}")
        
    except Exception as e:
        print(f"Error during index generation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
