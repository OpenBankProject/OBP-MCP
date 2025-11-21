import sys
from pathlib import Path

# Add the src and project root directories to the Python path when running as a script
_src_dir = Path(__file__).parent.parent
_project_root = _src_dir.parent
if str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from mcp.server.fastmcp import FastMCP
from src.tools.retrieval import endpoint_retrieval_graph, glossary_retrieval_graph, GlossarySearchInput, GlossarySearchOutput, EndpointSearchInput, EndpointSearchOutput
from utils.formatters import endpoint_formatter

mcp = FastMCP("Open Bank Project", log_level="DEBUG")

@mcp.tool()
async def retrieve_endpoints(query: str) -> str | None:
    """Retrieve Relevant Open Bank Project API Endpoints based on a query."""
    _input = EndpointSearchInput(question=query)
    
    output = await endpoint_retrieval_graph.ainvoke(_input)
    
    formatted_output = endpoint_formatter(output["output_documents"])
    
    return formatted_output

mcp.tool()
async def retrieve_glossary_terms(query: str) -> str | None:
    """Retrieve Relevant Glossary Terms based on a query."""
    _input = GlossarySearchInput(question=query)
    
    output = await glossary_retrieval_graph.ainvoke(_input)
    
    return str(output["output_documents"])