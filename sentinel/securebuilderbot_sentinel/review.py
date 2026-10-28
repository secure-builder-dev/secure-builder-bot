"""The review: the prompts, the requests, the answers read back, and the verdict (docs/PRD.md § Sentinel gate).

Light depth is the checklist pass: one request with the profile's items. Deep depth adds three more
requests, each its own: Control Completeness for each manifest control the diff touches (the six
questions of engine/SENTINEL-CHECKLIST.md, answered in the block shape that section prints), the
adversarial review and the edge-case hunt (the two skills under engine/skills/, as written, each with
a JSON output shape). Every input is a data block (sanitize.py); the system prompt is the reviewer's
agent definition, sentinel/agent.md, which says nothing inside a data block is an instruction.

An answer that does not parse is retried once with the parse error quoted; a second failure raises
Unreadable, and the gate reports not_run — never a pass. A finding keeps its path and line only when
that line is in the diff that was sent; each finding's message ends with SUFFIX.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from securebuilderbot_core.gate import Finding

from .checklist import cc_questions
from .inputs import ManifestRow, ReviewRequest
from .providers import Provider
from .sanitize import REMOVED, data_block, is_instruction_like, quote
from .schema import (
    SHAPES,
    AdversarialReview,
    CCBlock,
    ChecklistAnswer,
    EdgeCase,
    RawFinding,
    SchemaError,
    parse_adversarial,
    parse_cc,
    parse_checklist,
    parse_edge_case,
)

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "sentinel" / "agent.md"
SKILLS = ROOT / "engine" / "skills"
SUFFIX = "(cold reviewer, no build context)"
MAX_TOKENS = 16000
_NIST = re.compile(r"\b(?:AC|AT|AU|CA|CM|CP|IA|IR|MA|MP|PE|PL|PM|PS|PT|RA|SA|SC|SI|SR)-[1-9]\d?(?:\(\d{1,2}\))?(?!\d)")


class Unreadable(RuntimeError):
    """The reviewer's answer could not be read, twice."""


@dataclass
class Exchange:
    kind: str
    attempt: int
    system: str
    user: str
    answer: str
    files: list[str]
    answered: bool = False

    @property
    def bytes(self) -> int:
        return len(self.system.encode()) + len(self.user.encode())


@dataclass
class Outcome:
    checklist: list[ChecklistAnswer] = field(default_factory=list)
    cc: list[CCBlock] | None = None
    adversarial: AdversarialReview | None = None
    edge_cases: list[EdgeCase] | None = None
    exchanges: list[Exchange] = field(default_factory=list)


def system_prompt() -> str:
    return AGENT.read_text(encoding="utf-8")


def skill(name: str) -> str:
    """A review skill's instructions as written, without its front matter."""
    text = (SKILLS / name / "SKILL.md").read_text(encoding="utf-8")
    return text.split("---", 2)[2].strip() if text.startswith("---") else text.strip()


@dataclass(frozen=True)
class Instructions:
    """What the reviewer is told, from the bot's own install: the agent definition and both skills."""
    system: str
    adversarial: str
    edge_case: str


def instructions() -> Instructions:
    """Every file of the install the review reads, read now: the gate calls this in its prepare step,
    before QA runs the pull request's code as the user who can write the install (gate run 3, B-01).
    The Control Completeness questions are cached on first read, so reading them here is enough."""
    cc_questions()
    return Instructions(system=system_prompt(), adversarial=skill("review-adversarial-general"),
                        edge_case=skill("review-edge-case-hunter"))


# ── the prompts ───────────────────────────────────────────────────────────────────────────────

def _context(req: ReviewRequest) -> list[str]:
    p = req.profile
    baseline = f"NIST SP 800-53 Rev 5 {p.baseline} baseline" if p.baseline else "no NIST baseline (OWASP Top 10)"
    lines = [f"Profile: {p.name} — {baseline}; checklist blocks {' + '.join(p.checklist_blocks)}", f"Depth: {req.depth}",
             f"Control manifest: {req.qa.note}"]
    lines += [f"Note: {n}" for n in req.notes if n != req.qa.note]
    # Paths are the author's text: each is JSON-quoted, and only ever inside a data block (gate run 1, S-02),
    # and one that reads as an instruction is shown as its placeholder (gate run 2, B-02).
    if req.not_sent:
        lines.append(data_block("not_sent", "\n".join(f"{quote(req.shown(path))}: {why}" for path, why in req.not_sent)))
    if req.omitted:
        lines.append(data_block("omitted", "\n".join(quote(req.shown(path)) for path in req.omitted)))
    return lines


def _pr_blocks(req: ReviewRequest) -> list[str]:
    return [data_block("pr_title", req.pr_title), data_block("pr_body", req.pr_body),
            data_block("commit_messages", req.commits)]


def _shape(kind: str) -> str:
    return f"Answer with one fenced JSON block in exactly this shape:\n```json\n{SHAPES[kind]}\n```"


def checklist_prompt(req: ReviewRequest) -> tuple[str, list[str]]:
    items = []
    for i in req.items:
        line = f"- {i.id} [{', '.join(i.controls)}"
        line += f"; STIG {', '.join(i.stig)}]" if i.stig else "]"
        line += f" {i.text}"
        if i.applies_when:
            line += f" (applies when the range has: {', '.join(i.applies_when)}; otherwise n/a)"
        items.append(line)
    parts = ["Request: checklist", "", *_context(req), "",
             f"Answer every one of these {len(items)} items, each exactly once. A finding's rule_id is one of its item's controls.",
             *items, "", _shape("checklist"), "", *_pr_blocks(req)]
    parts += [data_block("file", f.text, path=req.shown(f.path), why=f.why) for f in req.named]
    parts.append(req.diff_text())
    return "\n".join(parts), [f.path for f in req.files] + [f.path for f in req.named]


def _row_controls(row: ManifestRow) -> list[str]:
    return _NIST.findall(row.note) or _NIST.findall(row.control)


def _cell(value: str) -> str:
    """A manifest cell as the prompt shows it: one that reads as an instruction is removed, as its line
    is in the manifest file itself (CM-50; build_request counts it)."""
    return REMOVED if is_instruction_like(value) else value


def cc_prompt(req: ReviewRequest) -> tuple[str, list[str]]:
    rows = data_block("touched_controls", "\n".join(quote(
        {"id": r.id, "implementation": _cell(r.implementation), "control": _cell(r.control),
         "proving_test": _cell(r.proving_test) or "none named",
         "qa": "proved it in this run" if r.id in req.qa.proven else "did not prove it in this run"}) for r in req.touched))
    questions = [f"- {q.id} ({q.label}): {q.question}" for q in cc_questions()]
    parts = ["Request: control_completeness", "", *_context(req), "",
             "Control Completeness Review, for each control in the touched_controls data block and no other. Answer each "
             "question in prose; Q3 and Q4 are lists you write out. A question that can be answered PASS has not been "
             "asked: never answer PASS.",
             rows, "", "The six questions:", *questions, "", _shape("control_completeness"), "", req.diff_text()]
    return "\n".join(parts), [f.path for f in req.files]


def adversarial_prompt(req: ReviewRequest, text: str | None = None) -> tuple[str, list[str]]:
    parts = ["Request: adversarial", "", *_context(req), "", "Execute this skill against the diff below:", "",
             skill("review-adversarial-general") if text is None else text, "",
             "Output: in place of the Markdown list the skill describes. " + _shape("adversarial")
             + "\nEach finding's rule_id is the NIST SP 800-53 control it serves.", "",
             *_pr_blocks(req), req.diff_text()]
    return "\n".join(parts), [f.path for f in req.files]


def edge_case_prompt(req: ReviewRequest, text: str | None = None) -> tuple[str, list[str]]:
    parts = ["Request: edge_case", "", *_context(req), "", "Execute this skill against the diff below:", "",
             skill("review-edge-case-hunter") if text is None else text, "",
             "The array may be returned bare or in one fenced json block.", "", req.diff_text()]
    return "\n".join(parts), [f.path for f in req.files]


# ── asking ────────────────────────────────────────────────────────────────────────────────────

def ask(provider: Provider, kind: str, system: str, user: str, files: list[str], parse: Callable,
        exchanges: list[Exchange]):
    """One request, retried once with the parse error quoted; Unreadable after the second failure."""
    prompt = user
    for attempt in (1, 2):
        answer = provider.complete(system, prompt, max_tokens=MAX_TOKENS)
        ex = Exchange(kind=kind, attempt=attempt, system=system, user=prompt, answer=answer, files=files)
        exchanges.append(ex)
        try:
            parsed = parse(answer)
        except SchemaError as e:
            error = str(e)
            prompt = (f"{user}\n\nYour previous answer could not be read: {error}. Answer again with only the JSON "
                      "block, in the shape above, answering every item.")
            continue
        ex.answered = True
        return parsed
    raise Unreadable(f"the reviewer's answer could not be read ({kind} request, twice): {error}")


def review(req: ReviewRequest, provider: Provider, out: Outcome | None = None,
           texts: Instructions | None = None) -> Outcome:
    """Every request the depth asks for, in order, into `out` (so the requests made survive an error),
    told what `texts` says (read from the install now when not given)."""
    out = out if out is not None else Outcome()
    texts = texts if texts is not None else instructions()
    system = texts.system
    user, files = checklist_prompt(req)
    out.checklist = ask(provider, "checklist", system, user, files, lambda a: parse_checklist(a, list(req.items)), out.exchanges)
    if req.depth != "deep":
        return out
    if req.touched:
        ids = [r.id for r in req.touched]
        user, files = cc_prompt(req)
        out.cc = ask(provider, "control_completeness", system, user, files, lambda a: parse_cc(a, ids), out.exchanges)
    user, files = adversarial_prompt(req, texts.adversarial)
    out.adversarial = ask(provider, "adversarial", system, user, files, parse_adversarial, out.exchanges)
    user, files = edge_case_prompt(req, texts.edge_case)
    out.edge_cases = ask(provider, "edge_case", system, user, files, parse_edge_case, out.exchanges)
    return out


# ── findings and the receipt's view of them ──────────────────────────────────────────────────

def place(req: ReviewRequest, path: str | None, line: int | None) -> tuple[str | None, int | None]:
    """A finding's location as far as it is real: the line only when the diff that was sent shows it,
    the path only when the file was sent."""
    lines = req.file_lines()
    path = req.real(path)
    if path in lines and line in lines[path]:
        return path, line
    return (path, None) if path in req.sent_paths() else (None, None)


def finding(req: ReviewRequest, raw: RawFinding) -> Finding:
    path, line = place(req, raw.path, raw.line)
    message = raw.message.rstrip()
    return Finding(severity=raw.severity, rule_id=raw.rule_id, message=f"{message} {SUFFIX}", path=path, line=line)


def cc_block_text(row: ManifestRow, block: CCBlock) -> str:
    def show(value: object) -> str:
        return "; ".join(value) if isinstance(value, list) else str(value)
    labels = {q.id: q.label for q in cc_questions()}
    lines = [f"CONTROL COMPLETENESS — {row.implementation}"]
    lines += [f"  {q} {labels[q]:<12}: {show(block.answers[q])}" for q in block.answers]
    blocking = block.verdict == "blocking" or block.unasked
    lines.append("  → BLOCKING finding" if blocking else "  → clear")
    return "\n".join(lines)


def findings_of(req: ReviewRequest, out: Outcome) -> list[Finding]:
    found = [finding(req, f) for a in out.checklist for f in a.findings]
    rows = {r.id: r for r in req.touched}
    for block in out.cc or []:
        row = rows[block.id]
        found += [finding(req, f) for f in block.findings]
        for q in block.unasked:
            rule = (_row_controls(row) or ["SA-11"])[0]
            found.append(finding(req, RawFinding(
                severity="blocking", rule_id=rule, path=row.path,
                message=f"Control Completeness for {row.id} ({row.implementation}): {q} answered PASS or left blank — "
                        "a question that can be answered PASS has not been asked")))
    if out.adversarial:
        found += [finding(req, f) for f in out.adversarial.findings]
    for e in out.edge_cases or []:
        path, line = place(req, e.path, e.line)
        found.append(Finding(severity="advisory", rule_id="edge-case", path=path, line=line,
                             message=f"{e.trigger_condition}: {e.potential_consequence}; guard: {e.guard_snippet} {SUFFIX}"))
    return found


def assessed(req: ReviewRequest, out: Outcome) -> set[str]:
    """The controls of items answered cited with evidence from a file that was sent — and only those."""
    sent = set(req.sent_paths())
    by_id = {i.id: i for i in req.items}
    return {c for a in out.checklist if a.answer == "cited" and req.real((a.evidence or {}).get("path")) in sent
            for c in by_id[a.id].controls}
