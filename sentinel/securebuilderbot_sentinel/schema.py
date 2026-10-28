"""The reviewer's answers, read against a schema (SPEC-sentinel.md § The review).

A model's answer is text from outside the gate. It is believed only as far as it parses: the last
fenced JSON block is extracted, checked against the shape its request asked for (required keys,
enums, types, no extra keys) by `validate` (CM-52), then against the request itself — every
checklist item answered exactly once, a citation carrying its evidence, an N/A carrying its reason, a
finding citing one of its item's controls, every touched control given its six answers. Anything
else raises SchemaError naming where and why; the gate quotes that error back once, and a second
failure makes the gate not_run — an unreadable answer is never a pass.

Standard library only: the schemas are small dicts, read by one recursive validator.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from securebuilderbot_standards import verify_citations

from .checklist import Item

_FENCE = re.compile(r"```(?:json|JSON)?[ \t]*\n(.*?)\n?```", re.S)
_LOCATION = re.compile(r"^(?P<path>.+?):(?P<line>\d+)(?:[-–]\d+)?$")
QUESTIONS = ("Q1", "Q2", "Q3", "Q4", "Q5", "Q6")


class SchemaError(ValueError):
    """The answer does not have the shape its request asked for; the message says where and why."""


# ── the validator ─────────────────────────────────────────────────────────────────────────────

def _type_name(schema: dict) -> str:
    if "any_of" in schema:
        return " or ".join(_type_name(s) for s in schema["any_of"])
    return schema["type"]


def _matches(value: object, kind: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
    }[kind]


def validate(value: object, schema: dict, at: str = "$") -> None:
    """CM-52: refuse a value that does not have the schema's shape; the error names the path."""
    if "any_of" in schema:
        for option in schema["any_of"]:
            try:
                validate(value, option, at)
                return
            except SchemaError:
                continue
        raise SchemaError(f"{at}: expected {_type_name(schema)}")
    kind = schema["type"]
    if not _matches(value, kind):
        raise SchemaError(f"{at}: expected {kind}")
    if kind == "object":
        required, optional = schema.get("required", {}), schema.get("optional", {})
        for key in required:
            if key not in value:
                raise SchemaError(f"{at}: missing key {key!r}")
        for key in value:
            if key not in required and key not in optional:
                raise SchemaError(f"{at}: unexpected key {key!r}")
        for key, sub in {**required, **optional}.items():
            if key in value:
                validate(value[key], sub, f"{at}.{key}")
    elif kind == "array":
        for i, item in enumerate(value):
            validate(item, schema["items"], f"{at}[{i}]")
    elif kind == "string":
        if "enum" in schema and value not in schema["enum"]:
            raise SchemaError(f"{at}: must be one of {', '.join(schema['enum'])}")
        if schema.get("min_len") and not value.strip():
            raise SchemaError(f"{at}: must not be empty")
    elif kind == "integer" and "min" in schema and value < schema["min"]:
        raise SchemaError(f"{at}: must be at least {schema['min']}")


STRING = {"type": "string", "min_len": 1}
LINE = {"any_of": [{"type": "integer", "min": 1}, {"type": "null"}]}
PATH = {"any_of": [{"type": "string"}, {"type": "null"}]}
FINDING = {"type": "object",
           "required": {"severity": {"type": "string", "enum": ["blocking", "advisory"]}, "rule_id": STRING, "message": STRING},
           "optional": {"path": PATH, "line": LINE}}
FINDINGS = {"type": "array", "items": FINDING}
CHECKLIST = {"type": "object", "required": {"items": {"type": "array", "items": {
    "type": "object",
    "required": {"id": STRING, "answer": {"type": "string", "enum": ["cited", "n/a", "finding"]}},
    "optional": {"evidence": {"type": "object", "required": {"path": STRING, "text": STRING}, "optional": {"line": LINE}},
                 "reason": STRING, "findings": FINDINGS},
}}}}
ANSWER = {"any_of": [{"type": "string"}, {"type": "array", "items": {"type": "string"}}]}
CC = {"type": "object", "required": {"controls": {"type": "array", "items": {
    "type": "object",
    "required": {"id": STRING, **{q.lower(): ANSWER for q in QUESTIONS},
                 "verdict": {"type": "string", "enum": ["clear", "blocking"]}},
    "optional": {"findings": FINDINGS},
}}}}
ADVERSARIAL = {"type": "object", "required": {"examined": STRING, "findings": FINDINGS}}
EDGE_CASE = {"type": "array", "items": {"type": "object", "required": {
    "location": {"type": "string"}, "trigger_condition": {"type": "string"},
    "guard_snippet": {"type": "string"}, "potential_consequence": {"type": "string"}}}}

SHAPES = {
    "checklist": json.dumps({"items": [
        {"id": "B-01", "answer": "cited", "evidence": {"path": "src/config.py", "line": 12, "text": "one sentence on what the line shows"}},
        {"id": "B-08", "answer": "n/a", "reason": "one sentence on why the item does not apply to this range"},
        {"id": "B-03", "answer": "finding", "findings": [{"severity": "blocking", "rule_id": "AC-3", "path": "src/routes.py",
                                                          "line": 40, "message": "one sentence: what is wrong and what would fix it"}]},
    ]}, indent=1),
    "control_completeness": json.dumps({"controls": [
        {"id": "CM-02", "q1": "answer in prose, or N/A: why", "q2": "the second write path, and whether the guard is on it",
         "q3": ["each entry point the hook does not cover"], "q4": ["each thing the verification does not verify"],
         "q5": "src/api.py:14", "q6": "answer in prose, or N/A: why", "verdict": "clear",
         "findings": []}]}, indent=1),
    "adversarial": json.dumps({"examined": "what you read, so an empty result says what it covered", "findings": [
        {"severity": "advisory", "rule_id": "SI-10", "path": "src/a.py", "line": 7, "message": "one sentence"}]}, indent=1),
    "edge_case": json.dumps([{"location": "src/a.py:10-12", "trigger_condition": "max 15 words",
                              "guard_snippet": "minimal code sketch", "potential_consequence": "max 15 words"}], indent=1),
}


# ── what comes back ───────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RawFinding:
    severity: str
    rule_id: str
    message: str
    path: str | None = None
    line: int | None = None


@dataclass(frozen=True)
class ChecklistAnswer:
    id: str
    answer: str
    evidence: dict | None = None
    reason: str = ""
    findings: tuple[RawFinding, ...] = ()


@dataclass(frozen=True)
class CCBlock:
    id: str
    answers: dict           # Q1..Q6 → the answer as given (a string or a list of strings)
    verdict: str
    findings: tuple[RawFinding, ...]
    unasked: tuple[str, ...]  # questions answered "PASS" or left blank: each a blocking finding


@dataclass(frozen=True)
class AdversarialReview:
    examined: str
    findings: tuple[RawFinding, ...]


@dataclass(frozen=True)
class EdgeCase:
    location: str
    trigger_condition: str
    guard_snippet: str
    potential_consequence: str
    path: str | None
    line: int | None


def extract_json(text: str) -> object:
    """The last fenced JSON block of an answer, or the whole answer when it is bare JSON."""
    blocks = _FENCE.findall(text or "")
    raw = blocks[-1] if blocks else (text or "").strip()
    if not raw or (not blocks and raw[0] not in "[{"):
        raise SchemaError("no fenced JSON block in the answer")
    try:
        return json.loads(raw)
    except ValueError as e:
        raise SchemaError(f"the JSON block is not valid JSON: {e}") from None


def _findings(raw: list) -> tuple[RawFinding, ...]:
    return tuple(RawFinding(severity=f["severity"], rule_id=f["rule_id"].strip(), message=f["message"].strip(),
                            path=f.get("path") or None, line=f.get("line")) for f in raw)


def _exactly_once(given: list[str], wanted: list[str], noun: str) -> None:
    seen: set[str] = set()
    for i in given:
        if i not in wanted:
            raise SchemaError(f"{i} is not {noun} of this request")
        if i in seen:
            raise SchemaError(f"{i} is answered twice")
        seen.add(i)
    missing = [i for i in wanted if i not in seen]
    if missing:
        raise SchemaError(f"not answered: {', '.join(missing)}")


def parse_checklist(text: str, items: list[Item]) -> list[ChecklistAnswer]:
    doc = extract_json(text)
    validate(doc, CHECKLIST)
    by_id = {i.id: i for i in items}
    _exactly_once([a["id"] for a in doc["items"]], list(by_id), "an item")
    out = []
    for a in doc["items"]:
        item, answer = by_id[a["id"]], a["answer"]
        if answer == "cited" and not a.get("evidence"):
            raise SchemaError(f"{item.id} is answered cited with no evidence (path, line, one sentence)")
        if answer == "n/a" and not a.get("reason"):
            raise SchemaError(f"{item.id} is answered n/a with no reason")
        findings = _findings(a.get("findings", []))
        if answer == "finding" and not findings:
            raise SchemaError(f"{item.id} is answered finding with no findings")
        for f in findings:
            if f.rule_id not in item.controls:
                raise SchemaError(f"{item.id}: a finding's rule_id must be one of the item's controls "
                                  f"({', '.join(item.controls)}), not {f.rule_id!r}")
        out.append(ChecklistAnswer(id=item.id, answer=answer, evidence=a.get("evidence"), reason=a.get("reason", ""),
                                   findings=findings if answer == "finding" else ()))
    order = list(by_id)
    return sorted(out, key=lambda x: order.index(x.id))


def _unasked(value: object) -> bool:
    if isinstance(value, list):
        return not any(v.strip() for v in value) or all(re.sub(r"\W", "", v).upper() == "PASS" for v in value)
    text = str(value).strip()
    return not text or re.sub(r"\W", "", text).upper() == "PASS"


def parse_cc(text: str, controls: list[str]) -> list[CCBlock]:
    doc = extract_json(text)
    validate(doc, CC)
    _exactly_once([b["id"] for b in doc["controls"]], controls, "a control")
    out = []
    for b in doc["controls"]:
        findings = _findings(b.get("findings", []))
        if b["verdict"] == "blocking" and not any(f.severity == "blocking" for f in findings):
            raise SchemaError(f"{b['id']}: verdict blocking with no blocking finding")
        answers = {q: b[q.lower()] for q in QUESTIONS}
        out.append(CCBlock(id=b["id"], answers=answers, verdict=b["verdict"], findings=findings,
                           unasked=tuple(q for q in QUESTIONS if _unasked(answers[q]))))
    return sorted(out, key=lambda x: controls.index(x.id))


def _active_control(cid: str) -> bool:
    cites = verify_citations(cid)
    return [c.id for c in cites] == [cid] and all(c.ok and c.kind == "nist" for c in cites)


def parse_adversarial(text: str) -> AdversarialReview:
    doc = extract_json(text)
    validate(doc, ADVERSARIAL)
    findings = _findings(doc["findings"])
    for f in findings:
        if not _active_control(f.rule_id):
            raise SchemaError(f"{f.rule_id!r} is not an active NIST SP 800-53 control; cite the control the finding serves")
    return AdversarialReview(examined=doc["examined"].strip(), findings=findings)


def parse_edge_case(text: str) -> list[EdgeCase]:
    doc = extract_json(text)
    validate(doc, EDGE_CASE)
    out = []
    for e in doc:
        loc = e["location"].strip()
        m = _LOCATION.match(loc)
        path = m.group("path") if m else (loc.rsplit(":", 1)[0] if ":" in loc else None)
        if path in ("N/A", ""):
            path = None
        out.append(EdgeCase(location=loc, trigger_condition=e["trigger_condition"], guard_snippet=e["guard_snippet"],
                            potential_consequence=e["potential_consequence"], path=path,
                            line=int(m.group("line")) if m else None))
    return out
