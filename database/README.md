# Vector Db Population Scripts

This directory contains scripts to populate the ChromaDB vector database with OBP data.

## populate_vector_db.py

Main script that fetches data from OBP endpoints and populates ChromaDB collections.

### What it does:

1. Fetches glossary data from: `{OBP_BASE_URL}/obp/{OBP_API_VERSION}/api/glossary`
2. Fetches swagger documentation from: `{OBP_BASE_URL}/obp/{OBP_API_VERSION}/resource-docs/{OBP_API_VERSION}/swagger?content=static`
3. Processes and chunks the data appropriately for vector search
4. Populates two ChromaDB collections:
   - `obp_glossary` - glossary terms and definitions
   - `obp_endpoints` - API endpoint documentation and schemas

### Usage:

from the root directory of the project, run:

```bash
python src/database/populate_vector_db.py [--endpoints {static,dynamic,all}]
```

### Requirements:

- OpenAI API key set in environment (for embeddings)
- OBP configuration in .env file:
  - OBP_BASE_URL
  - OBP_API_VERSION
  - CHROMADB_DIRECTORY


### Options:

- `--endpoints {static,dynamic,all}`: Type of endpoints to load (default: static)
  - `static`: Load only static endpoints
  - `dynamic`: Load only dynamic endpoints (Note: OBP API may not support this - will fetch all and filter)
  - `all`: Load all endpoints (static + dynamic)

The script will clear existing collections and repopulate them with fresh data.
