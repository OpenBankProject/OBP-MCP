from typing_extensions import TypedDict
from typing import List, Annotated
from agent.components.retrieval.endpoint_retrieval.components.reducers import add_docs
from langgraph.graph import MessagesState
from pydantic import BaseModel, Field

class InputState(BaseModel):
    question: str = Field(description="query to search vector database with")

class SelfRAGGraphState(TypedDict):
    """
    Represents the state of our graph.

    Attributes:
        question: question
        endpoint_tags: tags to filter the endpoints by before retrieval
        generation: LLM generation
        web_search: whether to add search
        documents: list of documents
        relevant_documents: list of filtered documents deemed to be relevant to the query
        retry_query: whether to rewrite question and retry vector search
        max_retries: maximum number of times to rewrite the query before generating an answer
        total_retries: running count of how many times RAG has been retried
        rewritten_question: question reformulated by the LLM
    """
    question: str
    endpoint_tags: List[str]
    generation: dict
    web_search: str # Implement web search later
    glossary_search: str # Implement OBP glossary search later
    documents: List[str]
    relevant_documents: Annotated[List[str], add_docs]
    retry_query: bool
    total_retries: int = 0
    rewritten_question: str
        
class OutputState(TypedDict):
    """
    Graph returns relevant endpoints
    """
    relevant_documents: Annotated[List[str], add_docs]