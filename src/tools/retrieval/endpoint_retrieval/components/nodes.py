import os
import json

from langchain_core.documents import Document
from typing import List
from agent.components.retrieval.endpoint_retrieval.components.states import OutputState
from agent.components.retrieval.retriever_config import get_retriever
from agent.components.retrieval.endpoint_retrieval.components.chains import retrieval_grader, endpoint_question_rewriter
from dotenv import load_dotenv

load_dotenv()

# Configuration from environment variables
RETRIEVER_BATCH_SIZE = int(os.getenv("ENDPOINT_RETRIEVER_BATCH_SIZE", "5"))
RETRIEVER_RETRY_THRESHOLD = int(os.getenv("ENDPOINT_RETRIEVER_RETRY_THRESHOLD", "2"))
RETRIEVER_MAX_RETRIES = int(os.getenv("ENDPOINT_RETRIEVER_MAX_RETRIES", "2"))

endpoint_retriever = get_retriever(
    collection_name="obp_endpoints",
    search_kwargs={"k": RETRIEVER_BATCH_SIZE}
)

async def retrieve_endpoints(state):
    """
    Retrieve documents

    Args:
        state (dict): The current graph state

    Returns:
        state (dict): New key added to state, documents, that contains retrieved documents
    """
    print("---RETRIEVE ENDPOINTS---")
    rewritten_question = state.get("rewritten_question", "")
    total_retries = state.get("total_retries", 0)

    if rewritten_question:
        question = state["rewritten_question"]
        total_retries += 1
    else:
        question = state["question"]
    # Retrieval
    documents = await endpoint_retriever.ainvoke(question)
    return {"documents": documents, "total_retries": total_retries}


async def return_documents(state) -> OutputState:
    """Return the relevant documents"""
    print("---RETRUN RELEVANT DOCUMENTS---")
    relevant_documents: List[Document] = state["relevant_documents"]

    output_docs = []

    for doc in relevant_documents:
        output_docs.append(
            {
                "method": doc.metadata["method"],
                "path": doc.metadata["path"],
                "operation_id": doc.metadata["operation_id"],
                "documentation": json.loads(doc.page_content),
            }
        )


    return {"output_documents": output_docs}


async def grade_documents(state):
    """
    Determines whether the retrieved documents are relevant to the question.

    Args:
        state (dict): The current graph state

    Returns:
        state (dict): Updates documents key with only filtered relevant documents
    """

    print("---CHECK DOCUMENT RELEVANCE TO QUESTION---")
    question = state["question"]
    documents = state["documents"]

    filtered_docs = []
    # web_search = False
    # glossary_search = False
    retry_query = False
    for d in documents:
        score = await retrieval_grader.ainvoke(
            {"question": question, "document": d.page_content}
        )
        grade = score.binary_score
        if grade == "yes":
            print(f"{d.metadata["method"]} - {d.metadata["path"]}", " [RELEVANT]")
            #print("---GRADE: DOCUMENT RELEVANT---")
            filtered_docs.append(d)
        else:
            print(f"{d.metadata["method"]} - {d.metadata["path"]}", " [NOT RELEVANT]")
            #print("---GRADE: DOCUMENT NOT RELEVANT---")
            continue

    # If there are less documents than the threshold then retry query after rewriting question
    retry_threshold = int(RETRIEVER_RETRY_THRESHOLD)

    if len(filtered_docs) < retry_threshold:
        retry_query=True
    else:
        retry_query=False

    #print("Documents: \n", "\n".join(f"{doc.metadata["method"]} - {doc.metadata["path"]}" for doc in filtered_docs))
    return {"documents": documents, "relevant_documents": filtered_docs, "question": question, "retry_query": retry_query}


async def transform_query(state):
    """
    Transform the query to produce a better question.

    Args:
        state (dict): The current graph state

    Returns:
        state (dict): Updates question key with a re-phrased question
    """

    print("---TRANSFORM QUERY---")
    question = state["question"]
    documents = state["documents"]
    total_retries = state.get("total_retries", 0)
    # Re-write question
    better_question = await endpoint_question_rewriter.ainvoke({"question": question})
    print(f"New query: \n{better_question}\n")
    return {"documents": documents, "rewritten_question": better_question}
