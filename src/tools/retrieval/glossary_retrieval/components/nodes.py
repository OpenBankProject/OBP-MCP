import logging
from src.tools.retrieval.retriever_config import get_retriever
from src.tools.retrieval.endpoint_retrieval.components.chains import retrieval_grader
from src.tools.retrieval.glossary_retrieval.components.states import SelfRAGGraphState, OutputState, InputState

logger = logging.getLogger("agent.components.retrieval.glossary_retrieval")

glossary_retriever = get_retriever("obp_glossary", search_kwargs={"k": 8})

async def retrieve_glossary(state):
    """
    Retrieve documents

    Args:
        state (dict): The current graph state

    Returns:
        state (dict): New key added to state, documents, that contains retrieved documents
    """
    logging.info("---RETRIEVE ITEMS---")
    rewritten_question = state.get("rewritten_question", "")
    total_retries = state.get("total_retries", 0)
    
    if rewritten_question:
        question = state["rewritten_question"]
        total_retries += 1
    else:
        question = state["question"]
    # Retrieval
    documents = await glossary_retriever.ainvoke(question)
    return {"documents": documents, "total_retries": total_retries}

async def grade_documents_glossary(state):
    """
    Determines whether the retrieved documents are relevant to the question.

    Args:
        state (dict): The current graph state

    Returns:
        state (dict): Updates documents key with only filtered relevant documents
    """

    logging.info("---CHECK DOCUMENT RELEVANCE TO QUESTION---")
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
            logging.info(f"{d.metadata["title"]}" + " [RELEVANT]")
            filtered_docs.append(d)
        else:
            logging.info(f"{d.metadata["title"]}" + " [NOT RELEVANT]")
            continue
        
    # If there are three or less relevant endpoints then retry query after rewriting question
    retry_threshold = 2
    
    if len(filtered_docs) <= retry_threshold:
        retry_query=True
        
    #logging.info("Documents: \n", "\n".join(f"{doc.metadata["title"]}" for doc in filtered_docs))
    return {"documents": documents, "relevant_documents": filtered_docs, "question": question, "retry_query": retry_query}
              
async def return_documents(state) -> OutputState:
    """Return the relevant documents"""
    logging.info("---RETRUN RELEVANT DOCUMENTS---")
    relevant_documents = state["relevant_documents"]
    return {"relevant_documents": relevant_documents}