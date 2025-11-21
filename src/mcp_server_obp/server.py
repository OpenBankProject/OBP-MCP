from mcp.server.fastmcp import FastMCP

from tools.retrieval import endpoint_retrieval_graph, glossary_retrieval_graph, GlossarySearchInput, GlossarySearchOutput, EndpointSearchInput, EndpointSearchOutput

mcp = FastMCP("Open Bank Project")

@mcp.tool
def retrieve_endpoints(query: str) -> str | None:
    """Retrieve Relevant Open Bank Project API Endpoints based on a query."""
    _input = EndpointSearchInput(question=query)
    
    output = endpoint_retrieval_graph.invoke(_input)
    
    return str(output["output_documents"])