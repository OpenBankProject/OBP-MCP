"""Tests for the X-Forwarded-For chain that call_obp_api sends to OBP-API."""

import asyncio
import importlib
import json
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from src.mcp_server_obp.forwarded_for import (
    canonical_address,
    headers_for_obp,
    outgoing_forwarded_for,
    split_chain,
    without_client_address_headers,
)


class TestCanonicalAddress:
    def test_ipv4_is_unchanged(self):
        assert canonical_address("203.0.113.7") == "203.0.113.7"

    def test_ipv6_mapped_ipv4_becomes_plain_ipv4(self):
        assert canonical_address("::ffff:203.0.113.7") == "203.0.113.7"

    def test_ipv6_loses_brackets_and_is_compressed(self):
        assert canonical_address("[2001:0db8:0000:0000:0000:0000:0000:0001]") == "2001:db8::1"

    def test_non_address_is_trimmed(self):
        assert canonical_address(" unknown ") == "unknown"


class TestSplitChain:
    def test_empty_and_missing(self):
        assert split_chain(None) == []
        assert split_chain("") == []

    def test_splits_and_drops_blanks(self):
        assert split_chain("203.0.113.7, ,::ffff:10.0.0.5") == ["203.0.113.7", "10.0.0.5"]


class TestOutgoingForwardedFor:
    def test_appends_request_chain_then_tcp_peer(self):
        assert (
            outgoing_forwarded_for("203.0.113.7, 10.0.0.1", "10.0.0.2", "10.0.0.3")
            == "203.0.113.7, 10.0.0.1, 10.0.0.2, 10.0.0.3"
        )

    def test_tcp_peer_alone(self):
        assert outgoing_forwarded_for(None, None, "::ffff:10.0.0.3") == "10.0.0.3"

    def test_no_tcp_peer_sends_nothing(self):
        assert outgoing_forwarded_for("6.6.6.6", None, None) is None


class TestHeadersForObp:
    def test_client_address_headers_are_removed_case_insensitively(self):
        headers = {"x-real-ip": "1.1.1.1", "FORWARDED": "for=1.1.1.1", "Consent-JWT": "jwt"}
        assert without_client_address_headers(headers) == {"Consent-JWT": "jwt"}

    def test_caller_chain_is_extended_with_what_this_server_saw(self, monkeypatch):
        import src.mcp_server_obp.forwarded_for as forwarded_for
        monkeypatch.setattr(forwarded_for, "http_request_addresses", lambda: (None, "10.0.0.9"))
        caller_headers = {"x-forwarded-for": "203.0.113.7, 10.0.0.1", "X-Real-IP": "6.6.6.6", "Consent-JWT": "jwt"}

        result = headers_for_obp(caller_headers)

        assert result == {"Consent-JWT": "jwt", "X-Forwarded-For": "203.0.113.7, 10.0.0.1, 10.0.0.9"}
        # The caller's dictionary is not changed.
        assert caller_headers["X-Real-IP"] == "6.6.6.6"

    def test_without_http_request_the_caller_chain_is_dropped(self, monkeypatch):
        import src.mcp_server_obp.forwarded_for as forwarded_for
        monkeypatch.setattr(forwarded_for, "http_request_addresses", lambda: (None, None))

        assert headers_for_obp({"X-Forwarded-For": "6.6.6.6"}) == {}

    def test_outside_any_request_there_is_no_peer(self):
        assert headers_for_obp(None) == {}


@pytest.fixture
def server_module(monkeypatch):
    """Import server.py with the endpoint index replaced by a single fake endpoint."""
    server = importlib.import_module("src.mcp_server_obp.server")
    endpoint = SimpleNamespace(
        path="/obp/VERSION/banks",
        method="GET",
        operation_id="OBPv4.0.0-getBanks",
        roles=[],
    )
    index = MagicMock()
    index.get_endpoint_schema.return_value = endpoint
    monkeypatch.setattr(server, "get_endpoint_index", lambda: index)
    monkeypatch.setenv("OBP_BASE_URL", "http://obp.example")
    monkeypatch.setenv("OBP_AUTHORIZATION_VIA", "consent")
    monkeypatch.setenv("OBP_OPEY_CONSUMER_KEY", "opey")
    return server


def _call(server, monkeypatch, headers, request_chain, tcp_peer):
    """Run call_obp_api with a fake MCP HTTP request, returning the headers sent to OBP-API."""
    # server.py imports the helpers under the name mcp_server_obp.forwarded_for.
    forwarded_for = sys.modules["mcp_server_obp.forwarded_for"]
    monkeypatch.setattr(forwarded_for, "http_request_addresses", lambda: (request_chain, tcp_peer))
    response = MagicMock(status_code=200)
    response.json.return_value = {"banks": []}
    request = MagicMock(return_value=response)
    monkeypatch.setattr(server.requests, "request", request)

    tool = getattr(server.call_obp_api, "fn", server.call_obp_api)
    result = asyncio.run(tool(ctx=None, endpoint_id="OBPv4.0.0-getBanks", headers=headers))

    assert json.loads(result)["status_code"] == 200
    return request.call_args.kwargs["headers"]


class TestCallObpApi:
    def test_appends_opey_address_to_the_chain_opey_sent(self, server_module, monkeypatch):
        sent = _call(
            server_module,
            monkeypatch,
            {"Consent-JWT": "jwt", "X-Forwarded-For": "203.0.113.7, 10.0.0.1", "X-Real-IP": "6.6.6.6"},
            request_chain=None,
            tcp_peer="10.0.0.2",
        )
        assert sent["X-Forwarded-For"] == "203.0.113.7, 10.0.0.1, 10.0.0.2"
        assert "X-Real-IP" not in sent
        assert sent["Consent-JWT"] == "jwt"
        assert sent["Consumer-Key"] == "opey"

    def test_does_not_change_the_callers_headers(self, server_module, monkeypatch):
        caller_headers = {"Consent-JWT": "jwt", "Authorization": "Bearer x"}
        sent = _call(server_module, monkeypatch, caller_headers, request_chain=None, tcp_peer="10.0.0.2")
        assert "Authorization" not in sent
        assert caller_headers == {"Consent-JWT": "jwt", "Authorization": "Bearer x"}

    def test_proxy_in_front_of_this_server_is_part_of_the_chain(self, server_module, monkeypatch):
        sent = _call(
            server_module,
            monkeypatch,
            {"Consent-JWT": "jwt", "X-Forwarded-For": "6.6.6.6"},
            request_chain="198.51.100.4",
            tcp_peer="10.0.0.8",
        )
        assert sent["X-Forwarded-For"] == "6.6.6.6, 198.51.100.4, 10.0.0.8"
