# Hybrid Tag-Based Endpoint Routing

## Overview

This document describes the new hybrid tag-based approach for endpoint discovery in the OBP-MCP server. This approach is designed to be more cost-effective and efficient than the previous RAG (Retrieval Augmented Generation) based system.

## Architecture

The hybrid approach follows a three-step process:

```
┌─────────────────────────────────────────────────────────────┐
│  User Query (e.g., "I need account endpoints")             │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  1. Tag Classification                                      │
│     → Identify relevant tags (Account, Bank, etc.)         │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  2. list_endpoints_by_tag(tags)                             │
│     → Returns lightweight endpoint summaries                │
│     → Only: id, name, method, path, summary, tags          │
│     → ~20-50 endpoints, minimal tokens                      │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Main LLM selects specific endpoint(s)                   │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  4. get_endpoint_schema(endpoint_id)                        │
│     → Fetch full schema ONLY for selected endpoint(s)      │
└─────────────────────┬───────────────────────────────────────┘
                      ▼
┌─────────────────────────────────────────────────────────────┐
│  5. call_obp_api(endpoint_id, params)                       │
│     → LLM constructs and executes request                  │
└─────────────────────────────────────────────────────────────┘
```

## Why This Approach?

### Cost Efficiency
- **No RAG infrastructure**: Eliminates vector database overhead
- **Minimal token usage**: Lightweight index (~50-100 tokens per endpoint)
- **On-demand schema loading**: Full schemas loaded only when needed
- **No grader/reformulator**: Simpler processing pipeline

### Performance
- **Fast tag-based filtering**: Quick endpoint discovery
- **Lazy schema loading**: Reduces initial load time
- **Caching support**: Schemas cached after first load

### Scalability
- **Handles 600+ endpoints**: Designed for large API surfaces
- **Tag-based organization**: Natural categorization
- **Extensible**: Easy to add new endpoints

## MCP Tools

### 1. `list_endpoints_by_tag`

Get available OBP API endpoints filtered by tags.

**Parameters:**
- `tags` (List[str]): List of tag names to filter endpoints
  - Examples: `["Account", "Transaction"]`, `["Bank"]`, `[]` (all endpoints)

**Returns:**
- JSON object with:
  - `count`: Number of matching endpoints
  - `endpoints`: Array of endpoint summaries

**Example:**
```python
list_endpoints_by_tag(["Account", "Bank"])
```

**Response:**
```json
{
  "count": 4,
  "endpoints": [
    {
      "id": "vVERSION-privateAccountsAtOneBank",
      "method": "GET",
      "path": "/obp/vVERSION/banks/{BANK_ID}/accounts",
      "operation_id": "vVERSION-privateAccountsAtOneBank",
      "summary": "Get Accounts at Bank (Private)",
      "tags": ["Account", "Bank"]
    },
    ...
  ]
}
```

### 2. `get_endpoint_schema`

Get the full OpenAPI schema for a specific endpoint.

**Parameters:**
- `endpoint_id` (str): The unique identifier (operationId) of the endpoint
  - Example: `"vVERSION-getBanks"`

**Returns:**
- JSON object with full OpenAPI schema including:
  - Parameters (path, query, body)
  - Request/response schemas
  - Descriptions and examples

**Example:**
```python
get_endpoint_schema("vVERSION-getBanks")
```

### 3. `call_obp_api`

Execute an OBP API request to a specific endpoint.

**Parameters:**
- `endpoint_id` (str): The unique identifier of the endpoint
- `path_params` (dict, optional): Path parameters (e.g., `{"BANK_ID": "123"}`)
- `query_params` (dict, optional): Query parameters (e.g., `{"limit": 10}`)
- `body` (dict, optional): Request body for POST/PUT requests
- `headers` (dict, optional): Additional HTTP headers

**Returns:**
- JSON object with:
  - `status_code`: HTTP status code
  - `endpoint_id`: The endpoint called
  - `method`: HTTP method used
  - `url`: Full URL called
  - `response`: API response data

**Example:**
```python
call_obp_api(
    "vVERSION-getBanks",
    query_params={"limit": 5}
)
```

## Usage Workflow

### Step 1: Discover Endpoints

```python
# Get all Account-related endpoints
result = list_endpoints_by_tag(["Account"])
```

### Step 2: Select Specific Endpoint

Review the summaries and identify the endpoint you need based on:
- Method (GET, POST, PUT, DELETE)
- Path (the URL pattern)
- Summary (brief description)

### Step 3: Get Full Schema (if needed)

```python
# Get detailed schema for the selected endpoint
schema = get_endpoint_schema("vVERSION-accountById")
```

### Step 4: Make API Call

```python
# Execute the API request
response = call_obp_api(
    "vVERSION-accountById",
    path_params={
        "BANK_ID": "my-bank-id",
        "ACCOUNT_ID": "my-account-id"
    },
    headers={
        "Authorization": "DirectLogin token=..."
    }
)
```

## Endpoint Index

The endpoint index is stored in `database/endpoint_index.json` and contains:

```json
{
  "endpoints": {
    "vVERSION-getBanks": {
      "id": "vVERSION-getBanks",
      "method": "GET",
      "path": "/obp/vVERSION/banks",
      "operation_id": "vVERSION-getBanks",
      "summary": "Get Banks",
      "tags": ["Bank"]
    },
    ...
  }
}
```

### Generating the Index

To regenerate the endpoint index from the OBP API:

```bash
# Generate index for static endpoints (default)
python scripts/generate_endpoint_index.py

# Generate index for dynamic endpoints
python scripts/generate_endpoint_index.py --endpoints dynamic

# Generate index for all endpoints
python scripts/generate_endpoint_index.py --endpoints all

# Specify custom output file
python scripts/generate_endpoint_index.py --output /path/to/custom_index.json
```

**Requirements:**
- `OBP_BASE_URL` environment variable (e.g., `https://apisandbox.openbankproject.com`)
- `OBP_API_VERSION` environment variable (e.g., `v5.1.0`)

## Deprecated: RAG-Based Tools

The following tools are now deprecated but remain available for backward compatibility:

### `retrieve_endpoints(query: str)`

**Status:** DEPRECATED

**Replacement:** Use `list_endpoints_by_tag()` → `get_endpoint_schema()` → `call_obp_api()`

**Why deprecated:**
- More expensive (uses vector database + LLM grading)
- Higher token usage
- Slower response time
- Complex RAG pipeline

## Migration Guide

If you're currently using `retrieve_endpoints()`:

**Old approach:**
```python
# Single step with RAG
endpoints = retrieve_endpoints("I need to get bank accounts")
# Returns: Full schemas for multiple endpoints (expensive)
```

**New approach:**
```python
# Step 1: Get lightweight summaries
endpoints = list_endpoints_by_tag(["Account", "Bank"])

# Step 2: Select the right endpoint (LLM can help here)
# Let's say we want "vVERSION-privateAccountsAtOneBank"

# Step 3: Get full schema only if needed
schema = get_endpoint_schema("vVERSION-privateAccountsAtOneBank")

# Step 4: Make the API call
response = call_obp_api(
    "vVERSION-privateAccountsAtOneBank",
    path_params={"BANK_ID": "gh.29.uk"}
)
```

## Benefits Summary

| Aspect | Old RAG Approach | New Hybrid Approach |
|--------|-----------------|---------------------|
| **Initial Load** | All schemas loaded | Lightweight index only |
| **Token Usage** | High (full schemas) | Low (summaries first) |
| **Response Time** | Slower (vector search + grading) | Faster (tag filtering) |
| **Infrastructure** | Vector DB required | Simple JSON file |
| **Accuracy** | Good | Better (explicit selection) |
| **Cost** | Higher | Lower |
| **Maintenance** | Complex | Simple |

## Technical Details

### Endpoint Index Structure

The `EndpointIndex` class (`src/tools/endpoint_index.py`) provides:

- **Lazy loading**: Schemas loaded on first access
- **Caching**: Loaded schemas cached in memory
- **Tag filtering**: Fast tag-based search
- **Reusability**: Leverages existing database loader code

### Key Design Decisions

1. **Use operationId as endpoint ID**: Ensures unique, stable identifiers
2. **Reuse existing fetch functions**: Avoids code duplication with `populate_vector_db.py`
3. **Separate index from schemas**: Keeps index lightweight
4. **Tag-based discovery**: Natural categorization for banking APIs

## Future Enhancements

Potential improvements for the future:

1. **Smart tag classifier**: Use a small LLM or rules engine to suggest tags from natural language queries
2. **Schema caching**: Persist loaded schemas to disk for faster subsequent loads
3. **Index versioning**: Track API version changes
4. **Advanced filtering**: Support for filtering by method, path patterns, etc.
5. **Batch operations**: Support multiple endpoint calls in a single request

## Support

For questions or issues with the hybrid routing system:
- Check the logs for detailed error messages
- Verify environment variables are set correctly
- Ensure the endpoint index is up to date
- Review endpoint summaries before requesting full schemas
