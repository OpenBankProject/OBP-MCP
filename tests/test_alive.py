"""Tests for the /alive liveness probe."""

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from src.mcp_server_obp.status import alive_endpoint


def test_alive_answers_true_as_json_and_is_not_cached():
    app = Starlette(routes=[Route("/alive", alive_endpoint, methods=["GET"])])
    response = TestClient(app).get("/alive")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.headers["cache-control"] == "no-store"
    assert response.text == "true"
