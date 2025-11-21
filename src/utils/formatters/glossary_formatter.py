import logging

logger = logging.getLogger("utils.formatters.glossary_formatter")

def glossary_formatter(glossary_terms: list[dict]) -> str:
    """
    Formats a list of glossary term dictionaries into a readable string.

    Args:
        glossary_terms (list[dict]): A list of glossary term dictionaries.

    Returns:
        str: A formatted string representing the glossary terms.
    """
    formatted_terms = []
    for term in glossary_terms:
        page_content = term.get("page_content", "N/A")
        
        formatted_term = (
            f"{page_content}\n"
            "----------------------------------------"
        )
        formatted_terms.append(formatted_term)

    return "\n".join(formatted_terms)
