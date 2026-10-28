"""Prompt injection: everything the reviewer reads is data (docs/PRD.md § Security of the bot itself).

The PR title and description, the commit messages, the diff and every named file are written by the
people whose change is under review. A line in any of them that looks like an instruction to the
reviewer is replaced by REMOVED before a prompt is built, and the count goes to the receipt, so an
author cannot talk the reviewer into a pass and an assessor can see that someone tried. The model
prompt then wraps every input in a delimited data block and says nothing inside one is an instruction;
a line that carries the delimiter itself is removed too, so an input can never close its own block.

The patterns are deliberately blunt: a false removal costs the reviewer one line, which it sees as
removed; a missed instruction can cost the verdict. A changed file's path is the author's text too: one
that reads as an instruction is shown as a numbered placeholder everywhere a prompt would show it
(inputs.py), and the real path stays in the receipt for people. Matching runs on a normalised copy (NFKC, format
characters such as zero-width spaces dropped, whitespace collapsed), so the same words written with
look-alike characters are still words. Secret-shaped strings are redacted on the way out as well:
nothing secret-shaped is ever sent to a model endpoint, whoever committed it.
"""

from __future__ import annotations

import json
import re
import unicodedata

from securebuilderbot_core.receipt import redact

REMOVED = "[removed: instruction-like text]"
DELIMITER = "<<<SB-"
INSTRUCTION = re.compile(
    r"ignore\s+(all|the|previous)\b"
    r"|\byou\s+are\s+(now|a)\b"
    r"|\bsystem\s*:"
    r"|\bassistant\s*:"
    r"|\bas\s+the\s+reviewer\b"
    r"|\bmark\s+this\s+(as\s+)?pass"
    r"|\bapprove\b"
    r"|\bdisregard\b"
    r"|<\|"
    r"|\[INST\]"
    r"|###\s*(system|instruction)",
    re.I,
)
_HUNK = re.compile(r"^(@@ [^@]* @@)(.*)$")
_PATH_SEPARATORS = re.compile(r"[_\-/.]+")


def _normalised(line: str) -> str:
    text = unicodedata.normalize("NFKC", line)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return re.sub(r"\s+", " ", text)


def is_instruction_like(line: str) -> bool:
    """CM-50: does this line read as an instruction to the reviewer, or carry the data-block delimiter?"""
    text = _normalised(line)
    return bool(INSTRUCTION.search(text)) or DELIMITER in text


def path_is_instruction_like(path: str) -> bool:
    """CM-50 for a path: the line rule, and the same rule with _ - / and . read as spaces, so
    ignore_all_previous_instructions.md is the sentence it spells (gate run 3, N-02). Paths only: in a
    code line those characters join an identifier, and approve_request() is code."""
    return is_instruction_like(path) or bool(INSTRUCTION.search(_PATH_SEPARATORS.sub(" ", _normalised(path))))


def sanitize_text(text: str) -> tuple[str, int]:
    """Free text (a PR description, a commit message, a named file): each instruction-like line replaced whole."""
    out, n = [], 0
    for line in text.split("\n"):
        if is_instruction_like(line):
            out.append(REMOVED)
            n += 1
        else:
            out.append(line)
    return "\n".join(out), n


def sanitize_diff(diff: str) -> tuple[str, int]:
    """A unified diff: the same rule, keeping each body line's +/-/space prefix and each hunk header's
    ranges, so the line numbers a finding cites still point where they did."""
    out, n = [], 0
    for line in diff.split("\n"):
        hunk = _HUNK.match(line)
        if hunk:
            if is_instruction_like(hunk.group(2)):
                out.append(f"{hunk.group(1)} {REMOVED}")
                n += 1
            else:
                out.append(line)
        elif line[:1] in ("+", "-", " ") and not line.startswith("diff "):
            if is_instruction_like(line[1:]):
                out.append(line[0] + REMOVED)
                n += 1
            else:
                out.append(line)
        elif is_instruction_like(line):
            out.append(REMOVED)
            n += 1
        else:
            out.append(line)
    return "\n".join(out), n


def redact_secrets(text: str) -> tuple[str, int]:
    """Every secret-shaped string replaced, by core's rule (the one the receipt is held to)."""
    return redact(text)


def quote(value: object) -> str:
    """CM-90: any value the author controls (a file path; a manifest row's cells) as one JSON ASCII line: a
    newline, a control character or an angle bracket survives only as an escape, so the value can
    neither end a line nor spell the data-block delimiter (gate run 1, S-02)."""
    return json.dumps(value, ensure_ascii=True).replace("<", "\\u003c").replace(">", "\\u003e")


def unsafe_text(value: str) -> bool:
    """A value that had to be encoded to be shown at all: a control or format character, or text that
    reads as an instruction or carries the delimiter. Only paths are asked, so the path rule applies."""
    return any(unicodedata.category(ch) in ("Cc", "Cf") for ch in value) or path_is_instruction_like(value)


def _attr(value: str) -> str:
    return quote(value)


def data_block(name: str, content: str, **attrs: str) -> str:
    """Content inside the delimiters the system prompt names as data. Attribute values are quoted and
    may not carry an angle bracket, so a file name cannot end the opening line early."""
    head = " ".join([f"name={_attr(name)}"] + [f"{k}={_attr(v)}" for k, v in attrs.items()])
    body = content if content.endswith("\n") or not content else content + "\n"
    return f"{DELIMITER}DATA {head}>>>\n{body}{DELIMITER}END name={_attr(name)}>>>"
