import logging
import json
from html_to_markdown import convert

logger = logging.getLogger("utils.formatters.endpoint_formatter")

def endpoint_formatter(endpoints: list[dict]) -> str:
    """
    Formats a list of endpoint dictionaries into a readable string.

    Args:
        endpoints (list[dict]): A list of endpoint dictionaries.

    Returns:
        str: A formatted string representing the endpoints.
    """
    formatted_endpoints = []
    for endpoint in endpoints:
        method = endpoint.get("method", "N/A")
        path = endpoint.get("path", "N/A")
        operation_id = endpoint.get("operation_id", "N/A")
        documentation = endpoint.get("documentation", {})
        
        markdown_description = _extract_description_markdown(documentation, method, path)
        documentation_no_description = documentation.copy()
        if path in documentation_no_description and method.lower() in documentation_no_description[path]:
            documentation_no_description[path][method.lower()].pop("description", None)

        formatted_endpoint = (
            f"Method: {method}\n"
            f"Path: {path}\n"
            f"Operation ID: {operation_id}\n"
            f"Description: \n{markdown_description}\n"
            f"Schema: {json.dumps(documentation_no_description, indent=2)}\n"
            "----------------------------------------"
        )
        formatted_endpoints.append(formatted_endpoint)

    return "\n".join(formatted_endpoints    )


def _extract_description_markdown(documentation: dict, method: str, path: str) -> str:
    """
    Extracts and converts the HTML description from the documentation to Markdown.

    Args:
        documentation (dict): The documentation dictionary.
        method (str): The HTTP method (e.g., 'get', 'post').

    Returns:
        str: The description in Markdown format.
    """
    try:
        html_description = documentation[path][method.lower()].get("description", "No description available.")
        markdown_description = convert(html_description)
        return markdown_description
    except Exception as e:
        logger.error(f"Error converting HTML to Markdown: {e}")
        return "No description available."