### EDGES
import os
from dotenv import load_dotenv

load_dotenv()
              
def decide_to_generate(state):
    """
    Determines whether to generate an answer, or re-generate a question.

    Args:
        state (dict): The current graph state

    Returns:
        str: Binary decision for next node to call
    """

    print("---ASSESS GRADED DOCUMENTS---")
    relevant_documents = state["relevant_documents"]
    retry_query = state["retry_query"]
    
    max_retries = int(os.getenv("ENDPOINT_RETRIEVER_MAX_RETRIES", 2))

    total_retries = state.get("total_retries", 0)
    print(f"Total retries: {total_retries}")
    print("Documents returned: \n", "\n".join(f"{doc.metadata["method"]} - {doc.metadata["path"]}" for doc in relevant_documents))
    
    if retry_query and (total_retries < max_retries):
        # All documents have been filtered check_relevance
        # We will re-generate a new query
        print(
            "---DECISION: ALL DOCUMENTS ARE NOT RELEVANT TO QUESTION, TRANSFORM QUERY---"
        )
        return "transform_query"
    else:
        # We have relevant documents, so finish
        print("---DECISION: RETURN DOCUMENTS---")
        return "return_documents"