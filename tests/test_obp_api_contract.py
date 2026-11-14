"""The contract between OBP-MCP and OBP-API.

obp-api-contract/contract.json lists every OBP-API call OBP-MCP makes on its own (the
meta calls: root, glossary, resource docs, swagger), with the response fields the code
reads. obp-api-contract/snapshot.json is what an OBP-API documents for those calls,
written by obp-api-contract/snapshot.py from its resource docs. These tests need no
server: they check that the list matches the code, and that every call reaches an
endpoint OBP-API documents, with every field the code reads. Retake the snapshot from a
new OBP-API build to learn whether that build breaks OBP-MCP.
"""

import ast
import json
from collections import Counter
from pathlib import Path

from database.obp_utils import DEFAULT_API_VERSION

ROOT = Path(__file__).resolve().parent.parent
CONTRACT_DIR = ROOT / "obp-api-contract"
SOURCE_DIRS = ["src", "database", "scripts"]

# Strings that contain an OBP-API path but make no call of their own: (file, needle, reason).
NOT_CALLS = [
    (
        "src/tools/endpoint_index.py",
        '_PATH_VERSION_RE = re.compile(r"^/obp/v(\\d+)\\.(\\d+)\\.(\\d+)/")',
        "matches the version of a path read from the resource docs (the v5.1.0 floor)",
    ),
    (
        "src/tools/endpoint_index.py",
        'return f"/obp/{MIN_OBP_API_VERSION}/" + path[m.end():]',
        "moves a resource doc path up to v5.1.0; call_obp_api calls it for the user",
    ),
]


def load(name):
    return json.loads((CONTRACT_DIR / name).read_text())


def calls():
    return load("contract.json")["calls"]


def key(call):
    return f"{call['verb']} {call['path']}"


def documented(call, snapshot):
    """The snapshot entry for a call, or None."""
    return next((e for e in snapshot["endpoints"] if key(e) == key(call)), None)


def undocumented_reads(call, fields):
    """The reads of `call` that `fields` does not document. A read written `a|b` is
    satisfied by either field."""
    return [read for read in call.get("reads", []) if not any(f in fields for f in read.split("|"))]


def builds_obp_path(text):
    return "/obp/v" in text or "/obp/{" in text


def docstring_nodes(tree):
    """The string constants that are docstrings of a module, class or function."""
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                out.add(id(body[0].value))
    return out


def obp_path_strings(rel, text):
    """String literals and f-strings in Python source that build an OBP-API path, skipping
    comments and docstrings: (line number, the source lines the string spans)."""
    tree = ast.parse(text, filename=rel)
    lines = text.splitlines()
    docstrings = docstring_nodes(tree)
    inside_fstrings = set()
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            inside_fstrings.update(id(v) for v in node.values)
            segment = ast.get_source_segment(text, node) or ""
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings or id(node) in inside_fstrings:
                continue
            segment = node.value
        else:
            continue
        if builds_obp_path(segment):
            span = "\n".join(lines[node.lineno - 1 : node.end_lineno])
            found.append((node.lineno, span))
    return sorted(found)


def obp_path_lines():
    """Every non-test source string that builds an OBP-API path:
    (file relative to the repo, line number, source)."""
    out = []
    for top in SOURCE_DIRS:
        for path in sorted((ROOT / top).rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            for lineno, span in obp_path_strings(rel, path.read_text()):
                out.append((rel, lineno, span))
    return out


def test_every_call_in_the_contract_is_in_its_source_file():
    """Tests that each listed call still exists: every needle of an entry occurs in the entry's source file."""
    gone = []
    for call in calls():
        text = (ROOT / call["source"]).read_text()
        gone += [f"{key(call)} - {needle}" for needle in call["needles"] if needle not in text]
    assert gone == []


def test_every_obp_api_call_in_the_source_is_in_the_contract():
    """Tests coverage: a string that builds an OBP-API path must sit on a line holding a needle of a call
    listed for that file (or of NOT_CALLS), so a new call cannot reach OBP-API without its fields being recorded."""
    known = [(c["source"], n) for c in calls() for n in c["needles"]]
    known += [(file, needle) for file, needle, _ in NOT_CALLS]
    unlisted = [
        f"{file}:{n} {span.strip()}"
        for file, n, span in obp_path_lines()
        if not any(source == file and needle.strip() in span for source, needle in known)
    ]
    assert unlisted == []


def test_not_calls_are_still_in_the_source():
    """Tests that every NOT_CALLS entry still names text in its file, so the list does not keep stale entries."""
    gone = [f"{file} - {needle}" for file, needle, _ in NOT_CALLS if needle not in (ROOT / file).read_text()]
    assert gone == []


def test_the_contract_paths_use_the_default_api_version():
    """Tests that every version in a contract path is DEFAULT_API_VERSION (database/obp_utils.py), the version
    OBP_VERSION_TO_CALL and API_VERSION_OF_INTEREST fall back to; change both together."""
    wrong = [
        key(call)
        for call in calls()
        for segment in call["path"].split("/")
        if segment.startswith("v") and segment[1:2].isdigit() and segment != DEFAULT_API_VERSION
    ]
    assert wrong == []


def test_the_snapshot_was_taken_for_this_contract():
    """Tests that snapshot.json holds exactly the calls of contract.json; otherwise rerun snapshot.py."""
    snapshot = load("snapshot.json")
    assert Counter(map(key, calls())) == Counter(map(key, snapshot["endpoints"]))


def test_every_call_reaches_an_endpoint_obp_api_documents():
    """Tests that each call's version and path name a documented endpoint, unless the entry records why not
    (undocumented_endpoint). A recorded gap that OBP-API has since documented fails too, so the note goes."""
    snapshot = load("snapshot.json")
    problems = []
    for call in calls():
        entry = documented(call, snapshot) or {}
        missing = entry.get("missing", False)
        known_gap = call.get("undocumented_endpoint")
        if missing and not known_gap:
            problems.append(f"{key(call)}: no documented endpoint")
        elif not missing and known_gap:
            problems.append(f"{key(call)}: now documented as {entry.get('operation_id')}; drop undocumented_endpoint")
        if entry.get("ambiguous"):
            problems.append(f"{key(call)}: matches several endpoints {entry['ambiguous']}")
    assert problems == []


def test_every_field_the_code_reads_is_documented():
    """Tests that each field the code reads is in the documented response of its endpoint, unless the entry
    lists it in undocumented_fields; a listed field that OBP-API now documents fails, so the list shrinks."""
    snapshot = load("snapshot.json")
    problems = []
    for call in calls():
        entry = documented(call, snapshot)
        if entry is None or entry.get("missing"):
            continue
        fields = set(entry.get("fields", []))
        known = set(call.get("undocumented_fields", []))
        for read in undocumented_reads(call, fields):
            if read not in known:
                problems.append(f"{key(call)} ({entry['operation_id']}): reads {read}, not documented")
        for field in sorted(known & fields):
            problems.append(f"{key(call)}: {field} is now documented; drop it from undocumented_fields")
    assert problems == []


def test_a_renamed_or_removed_field_is_reported():
    """Tests the check itself: with `glossary_items[].title` gone from the documented fields, the glossary read is
    reported, and a read with an alternative (`a|b`) passes on either field."""
    glossary = {"reads": ["glossary_items", "glossary_items[].title"]}
    renamed = {"glossary_items", "glossary_items[]", "glossary_items[].name"}
    assert undocumented_reads(glossary, renamed) == ["glossary_items[].title"]
    either = {"reads": ["glossary_items[].title|glossary_items[].name"]}
    assert undocumented_reads(either, renamed) == []
    assert undocumented_reads(either, set()) == ["glossary_items[].title|glossary_items[].name"]


def test_the_path_scan_finds_obp_api_paths_and_skips_comments_and_docstrings():
    """Tests the coverage scan itself: plain strings and f-strings with an OBP-API path are found; comments,
    docstrings and other /obp/ paths are not."""
    source = '''"""Module docstring with /obp/v7.0.0/root."""
# a comment with /obp/v7.0.0/banks
def f(base, v):
    """Docstring with /obp/v5.1.0/banks."""
    a = f"{base}/obp/{v}/root"
    b = "/obp/v4.0.0/x"
    c = "/obp/dynamic-entity/x"
    return a, b, c
'''
    assert [n for n, _ in obp_path_strings("example.py", source)] == [5, 6]
