"""The reviewer's answers are read against a schema, never trusted (SPEC-sentinel.md § The review): a
fenced JSON block, required keys, enums, types, and every item answered exactly once. An answer that
does not parse is an error the gate retries once and then reports as not run — never a pass."""

from __future__ import annotations

import json

import pytest

from securebuilderbot_sentinel.checklist import load_items
from securebuilderbot_sentinel.schema import (
    SHAPES,
    SchemaError,
    extract_json,
    parse_adversarial,
    parse_cc,
    parse_checklist,
    parse_edge_case,
    validate,
)

ITEMS = [i for i in load_items() if i.id in ("B-01", "B-08")]


def fenced(doc) -> str:
    return "Here is my review.\n\n```json\n" + json.dumps(doc) + "\n```\n"


def good_checklist(**override):
    items = [{"id": "B-01", "answer": "cited", "evidence": {"path": "src/a.py", "line": 3, "text": "reads the key from the environment"}},
             {"id": "B-08", "answer": "n/a", "reason": "no SQL in the range"}]
    for i in items:
        i.update(override.get(i["id"], {}))
    return {"items": items}


def test_the_last_fenced_json_block_is_the_answer():
    assert extract_json("```json\n{\"a\": 1}\n```\nthen\n```json\n{\"a\": 2}\n```") == {"a": 2}
    assert extract_json("```\n[1]\n```") == [1]
    assert extract_json('  {"bare": true} ') == {"bare": True}


@pytest.mark.parametrize("text, message", [
    ("I think it is fine.", "no fenced JSON block"),
    ("```json\n{not json}\n```", "not valid JSON"),
    ("", "no fenced JSON block"),
])
def test_an_answer_with_no_json_is_refused(text, message):
    with pytest.raises(SchemaError, match=message):
        extract_json(text)


@pytest.mark.parametrize("value, schema, message", [
    ({"a": 1}, {"type": "object", "required": {"b": {"type": "string"}}}, r"\$: missing key 'b'"),
    ({"a": 1}, {"type": "object", "required": {}}, r"\$: unexpected key 'a'"),
    ({"a": "x"}, {"type": "object", "required": {"a": {"type": "integer"}}}, r"\$.a: expected integer"),
    ({"a": True}, {"type": "object", "required": {"a": {"type": "integer"}}}, r"\$.a: expected integer"),
    ({"a": 0}, {"type": "object", "required": {"a": {"type": "integer", "min": 1}}}, r"\$.a: must be at least 1"),
    ({"a": "z"}, {"type": "object", "required": {"a": {"type": "string", "enum": ["x", "y"]}}}, r"\$.a: must be one of x, y"),
    ({"a": " "}, {"type": "object", "required": {"a": {"type": "string", "min_len": 1}}}, r"\$.a: must not be empty"),
    ([1, "x"], {"type": "array", "items": {"type": "integer"}}, r"\$\[1\]: expected integer"),
    ("x", {"type": "array", "items": {"type": "integer"}}, r"\$: expected array"),
    ("x", {"any_of": [{"type": "integer"}, {"type": "null"}]}, r"\$: expected integer or null"),
])
def test_validate_names_where_and_why(value, schema, message):
    with pytest.raises(SchemaError, match=message):
        validate(value, schema)


def test_validate_accepts_what_matches():
    validate({"a": 1, "b": None}, {"type": "object", "required": {"a": {"type": "integer"}},
                                    "optional": {"b": {"any_of": [{"type": "string"}, {"type": "null"}]}}})


def test_a_good_checklist_answer_is_read():
    answers = parse_checklist(fenced(good_checklist()), ITEMS)
    assert [(a.id, a.answer) for a in answers] == [("B-01", "cited"), ("B-08", "n/a")]
    assert answers[0].evidence == {"path": "src/a.py", "line": 3, "text": "reads the key from the environment"}
    assert answers[1].reason == "no SQL in the range"


@pytest.mark.parametrize("override, message", [
    ({"B-01": {"answer": "ok"}}, r"answer: must be one of cited, n/a, finding"),
    ({"B-01": {"evidence": None}}, r"evidence: expected object"),
    ({"B-01": {"evidence": {"path": "src/a.py", "line": 3}}}, r"evidence: missing key 'text'"),
    ({"B-08": {"reason": ""}}, r"reason: must not be empty"),
    ({"B-08": {"answer": "finding"}}, r"B-08 is answered finding with no findings"),
    ({"B-08": {"answer": "finding", "findings": [{"severity": "blocking", "rule_id": "AC-3", "message": "m"}]}},
     r"B-08: a finding's rule_id must be one of the item's controls \(SI-10\), not 'AC-3'"),
    ({"B-01": {"id": "B-99"}}, r"B-99 is not an item of this request"),
])
def test_a_bad_checklist_answer_is_refused_with_the_reason(override, message):
    doc = good_checklist(**override)
    if "B-01" in override and "evidence" in override["B-01"] and override["B-01"]["evidence"] is None:
        doc["items"][0]["evidence"] = None
    with pytest.raises(SchemaError, match=message):
        parse_checklist(fenced(doc), ITEMS)


def test_every_item_must_be_answered_exactly_once():
    doc = good_checklist()
    with pytest.raises(SchemaError, match="not answered: B-08"):
        parse_checklist(fenced({"items": doc["items"][:1]}), ITEMS)
    with pytest.raises(SchemaError, match="B-01 is answered twice"):
        parse_checklist(fenced({"items": doc["items"] + doc["items"][:1]}), ITEMS)


def test_a_finding_answer_carries_its_findings():
    doc = good_checklist(**{"B-08": {"answer": "finding", "findings": [
        {"severity": "blocking", "rule_id": "SI-10", "path": "src/q.py", "line": 9, "message": "the query concatenates input"}]}})
    answers = parse_checklist(fenced(doc), ITEMS)
    assert answers[1].findings[0].rule_id == "SI-10" and answers[1].findings[0].line == 9


CC_OK = {"id": "CM-02", "q1": "N/A: the scope takes no nested input", "q2": "One write path: list(); no bulk read",
         "q3": ["count() is not scoped"], "q4": ["does not check the tenant is active"], "q5": "src/api.py:14",
         "q6": "N/A: rejects no input", "verdict": "clear"}


def test_a_control_completeness_block_is_read():
    blocks = parse_cc(fenced({"controls": [CC_OK]}), ["CM-02"])
    assert blocks[0].id == "CM-02" and blocks[0].answers["Q3"] == ["count() is not scoped"]
    assert blocks[0].unasked == ()


def test_a_question_answered_pass_or_left_blank_is_named():
    blocks = parse_cc(fenced({"controls": [{**CC_OK, "q2": "PASS", "q4": []}]}), ["CM-02"])
    assert blocks[0].unasked == ("Q2", "Q4")


def test_a_control_completeness_answer_must_cover_exactly_the_touched_controls():
    with pytest.raises(SchemaError, match="not answered: CM-03"):
        parse_cc(fenced({"controls": [CC_OK]}), ["CM-02", "CM-03"])
    with pytest.raises(SchemaError, match="CM-09 is not a control of this request"):
        parse_cc(fenced({"controls": [CC_OK, {**CC_OK, "id": "CM-09"}]}), ["CM-02"])
    with pytest.raises(SchemaError, match="verdict blocking with no blocking finding"):
        parse_cc(fenced({"controls": [{**CC_OK, "verdict": "blocking"}]}), ["CM-02"])


def test_an_adversarial_answer_names_what_it_examined_and_cites_real_controls():
    review = parse_adversarial(fenced({"examined": "the two handlers", "findings": [
        {"severity": "advisory", "rule_id": "AC-3", "path": "a.py", "line": 2, "message": "m"}]}))
    assert review.examined == "the two handlers" and review.findings[0].rule_id == "AC-3"
    with pytest.raises(SchemaError, match="'AC-99' is not an active NIST SP 800-53 control"):
        parse_adversarial(fenced({"examined": "x", "findings": [{"severity": "advisory", "rule_id": "AC-99", "message": "m"}]}))
    with pytest.raises(SchemaError, match="examined: must not be empty"):
        parse_adversarial(fenced({"examined": "", "findings": []}))


def test_the_edge_case_answer_is_the_skills_own_shape():
    found = parse_edge_case(fenced([{"location": "src/a.py:10-12", "trigger_condition": "empty list",
                                     "guard_snippet": "if not xs: return []", "potential_consequence": "IndexError"}]))
    assert (found[0].path, found[0].line) == ("src/a.py", 10)
    assert parse_edge_case("```json\n[]\n```") == []
    with pytest.raises(SchemaError, match=r"\$\[0\]: unexpected key 'severity'"):
        parse_edge_case(fenced([{"location": "a", "trigger_condition": "b", "guard_snippet": "c",
                                 "potential_consequence": "d", "severity": "blocking"}]))


def test_a_location_with_no_line_is_lineless():
    found = parse_edge_case(fenced([{"location": "src/a.py:hunk", "trigger_condition": "t", "guard_snippet": "g",
                                     "potential_consequence": "p"}]))
    assert (found[0].path, found[0].line) == ("src/a.py", None)


def test_every_kind_has_an_example_shape_for_the_prompt():
    assert set(SHAPES) == {"checklist", "control_completeness", "adversarial", "edge_case"}
    for shape in SHAPES.values():
        json.loads(shape)
