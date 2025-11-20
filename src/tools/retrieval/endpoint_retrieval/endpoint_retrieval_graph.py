from langgraph.graph import END, StateGraph, START
from agent.components.retrieval.endpoint_retrieval.components.states import SelfRAGGraphState, OutputState, InputState
from agent.components.retrieval.endpoint_retrieval.components.nodes import grade_documents, retrieve_endpoints, transform_query, return_documents
from agent.components.retrieval.endpoint_retrieval.components.edges import decide_to_generate

workflow = StateGraph(SelfRAGGraphState, input=InputState, output=OutputState)

# Define the nodes

workflow.add_node("retrieve_endpoints", retrieve_endpoints)  # retrieve
workflow.add_node("grade_documents", grade_documents)  # grade documents
workflow.add_node("transform_query", transform_query)  # transform_query
workflow.add_node("return_documents", return_documents)

# Build graph
workflow.add_edge(START, "retrieve_endpoints")
workflow.add_edge("retrieve_endpoints", "grade_documents")
workflow.add_conditional_edges(
    "grade_documents",
    decide_to_generate,
    {
        "transform_query": "transform_query",
        "return_documents": "return_documents",
    },
)
workflow.add_edge("transform_query", "retrieve_endpoints")
workflow.add_edge("return_documents", END)

# Compile
endpoint_retrieval_graph = workflow.compile(checkpointer=False)