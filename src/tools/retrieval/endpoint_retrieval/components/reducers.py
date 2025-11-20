from typing import List
from langchain_core.documents import Document

def add_docs(left: List[Document], right: List[Document]) -> List[Document]:
    """
    Reducer that adds documents to the list of documents, or updates them if they have the same ID
    """
    if not left:
        left = []
    
    if not right:
        right = []
        
    docs = left.copy()

    left_id_to_idx = {doc.metadata["document_id"]: idx for idx, doc in enumerate(docs)}
    for doc in right:
        idx = left_id_to_idx.get(doc.metadata["document_id"])
        if idx is not None:
            docs[idx] = doc
        else:
            docs.append(doc)
    return docs