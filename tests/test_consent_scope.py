"""Tests for the consent my_resources scope derived from an endpoint path."""

from src.mcp_server_obp.consent_scope import consent_bank_id, my_resources_for


def test_system_level_personal_entity_read():
    assert my_resources_for("/obp/dynamic-entity/my/customer_preferences", "GET", None) == {
        "personal_dynamic_entities": [
            {"bank_id": "SYS", "entity_name": "customer_preferences", "actions": ["read"]}
        ]
    }


def test_system_level_personal_entity_write_ignores_bank_id():
    out = my_resources_for("/obp/dynamic-entity/my/customer_preferences/CUSTOMER_PREFERENCES_ID", "PUT", "some-bank")
    assert out == {
        "personal_dynamic_entities": [
            {"bank_id": "SYS", "entity_name": "customer_preferences", "actions": ["write"]}
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


def test_bank_level_entity_without_a_bank_id_needs_nothing():
    # An empty bank_id would name the system space, so no entry is better than the wrong one.
    assert my_resources_for("/obp/dynamic-entity/banks/BANK_ID/my/notes", "GET", None) is None


def test_method_may_be_an_enum_like_object():
    class Method:
        value = "delete"

    out = my_resources_for("/obp/dynamic-entity/my/notes/NOTES_ID", Method(), None)
    assert out["personal_dynamic_entities"][0]["actions"] == ["write"]


BANK_ROLE = {"role": "CanGetDynamicEntityDefinitions", "requires_bank_id": True}
SYSTEM_ROLE = {"role": "CanGetDynamicEntityDiagnostics", "requires_bank_id": False}


def test_consent_bank_id_from_path():
    assert consent_bank_id({"BANK_ID": "gh.29.uk"}, {}, {}, [BANK_ROLE]) == "gh.29.uk"


def test_consent_bank_id_from_body():
    assert consent_bank_id({}, {}, {"bank_id": "gh.29.uk"}, [BANK_ROLE]) == "gh.29.uk"


def test_consent_bank_id_bank_scoped_role_without_bank_is_system_space():
    # e.g. GET /obp/v6.0.0/management/system-dynamic-entities checks the role at SYS
    assert consent_bank_id({}, {}, {}, [BANK_ROLE]) == "SYS"


def test_consent_bank_id_explicit_empty_bank_is_not_overridden():
    assert consent_bank_id({}, {}, {"bank_id": ""}, [BANK_ROLE]) is None


def test_consent_bank_id_system_role_needs_no_bank():
    assert consent_bank_id({}, {}, {}, [SYSTEM_ROLE]) is None
