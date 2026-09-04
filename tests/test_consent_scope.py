"""Tests for the consent my_resources scope derived from an endpoint path."""

from src.mcp_server_obp.consent_scope import my_resources_for


def test_system_level_personal_entity_read():
    assert my_resources_for("/obp/dynamic-entity/my/customer_preferences", "GET", None) == {
        "personal_dynamic_entities": [
            {"bank_id": "", "entity_name": "customer_preferences", "actions": ["read"]}
        ]
    }


def test_system_level_personal_entity_write_ignores_bank_id():
    out = my_resources_for("/obp/dynamic-entity/my/customer_preferences/CUSTOMER_PREFERENCES_ID", "PUT", "some-bank")
    assert out == {
        "personal_dynamic_entities": [
            {"bank_id": "", "entity_name": "customer_preferences", "actions": ["write"]}
        ]
    }


def test_bank_level_personal_entity_uses_bank_id():
    out = my_resources_for("/obp/dynamic-entity/banks/BANK_ID/my/notes", "POST", "gh.29.uk")
    assert out == {
        "personal_dynamic_entities": [{"bank_id": "gh.29.uk", "entity_name": "notes", "actions": ["write"]}]
    }


def test_non_personal_paths_need_nothing():
    assert my_resources_for("/obp/dynamic-entity/customer_preferences", "GET", None) is None
    assert my_resources_for("/obp/dynamic-entity/community/customer_preferences", "GET", None) is None
    assert my_resources_for("/obp/v6.0.0/my/accounts", "GET", None) is None
    assert my_resources_for(None, None, None) is None


def test_method_may_be_an_enum_like_object():
    class Method:
        value = "delete"

    out = my_resources_for("/obp/dynamic-entity/my/notes/NOTES_ID", Method(), None)
    assert out["personal_dynamic_entities"][0]["actions"] == ["write"]
