"""The receipt: one file per run, written for an assessor (docs/PRD.md § What the user sees).

receipt.json is the contract and receipt.md is rendered from it. It names what was checked, against
which profile and catalog version, what each gate found, which files went to a model endpoint, and
the baseline's controls no gate assessed, so nothing is implied that was not checked.

Nothing the bot writes is ever a secret value. The runner redacts every gate's reason and finding
text with `redact` before any of the three outputs or stdout sees it; then, as a second refusal,
every string and key in the receipt is checked against the same patterns and a match refuses the write.
Writes are atomic (a temporary file, then a rename), so a reader never sees half a receipt.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

SCHEMA = "securebuilderbot.receipt/1"
SECRET = re.compile(
    r"AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{36,}"
    r"|gl(?:pat|dt|rt|cbt|ptt|ft|ffct|oas|imt|soat)-[A-Za-z0-9_-]{20,}|glagent-[A-Za-z0-9_-]{50,}|GR1348941[A-Za-z0-9_-]{20,}"
    r"|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}"
    r"|(password|passwd|secret|api[_-]?key|client[_-]?secret|token)\s*[:=]\s*[\"'][A-Za-z0-9+/=_@#$%^&*!.-]{12,}[\"']",
    re.I,
)


REDACTED = "[redacted: secret-shaped string]"
SHOWABLE = re.compile(r"[A-Za-z0-9_.()-]{1,40}")


def shown(value: object) -> str:
    """A value as an error message may repeat it: short, plain and not secret-shaped, or not at all."""
    if isinstance(value, str) and SHOWABLE.fullmatch(value) and not SECRET.search(value):
        return repr(value)
    return "(a value not shown)"


def redact(text: str) -> tuple[str, int]:
    """The text with every secret-shaped match replaced, and how many there were."""
    return SECRET.subn(REDACTED, text)


class ReceiptError(RuntimeError):
    """The receipt would have carried a secret-shaped string; nothing was written."""


def _strings(value: object, at: str = "$"):
    if isinstance(value, str):
        yield at, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield f"{at} (a key)", str(k)
            yield from _strings(v, f"{at}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            yield from _strings(v, f"{at}[{i}]")


def check_no_secrets(receipt: dict) -> None:
    for where, text in _strings(receipt):
        if SECRET.search(text):
            raise ReceiptError(f"the receipt would have carried a secret-shaped string at {where}; nothing was written")


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _config_source(c: dict) -> str:
    source = {"base": "the base commit", "pull request": "this pull request (the base has none yet)",
              "outside the checkout": "outside the checkout"}.get(c.get("source", ""), "the file given")
    changed = c.get("changed_by_pr") or []
    return source + (f"; this pull request changes {', '.join(changed)}, which applies once merged" if changed else "")


def _line(text: object) -> str:
    """One line: a gate's reason or finding can quote the code under review, and a newline in it would
    start a heading that the publishers read as another gate's section."""
    return " ".join(str(text).splitlines())


def render_md(r: dict) -> str:
    p = r["profile"]
    out = [f"# Receipt {r['run_id']}", "",
           f"- Range: `{r['base'][:12]}..{r['head'][:12]}` ({r['depth']})",
           f"- Profile: {p['name']} — {p['title']}",
           f"- Baseline: {p['baseline'] or 'none'} ({p['controls']} controls, NIST SP 800-53 Rev 5 catalog {p['catalog_version']})",
           f"- Config: `{r['config']['path']}` sha256 {r['config']['sha256'][:16]}…, from {_config_source(r['config'])}",
           f"- Started {r['started']}, finished {r['finished']}", "", "## Gates", ""]
    for name, g in r["gates"].items():
        out.append(f"### {name}: {g['status']}" + (f" — {_line(g['reason'])}" if g["reason"] else ""))
        for f in g["findings"]:
            loc = f" `{_line(f['path'])}:{f['line']}`" if f.get("path") and f.get("line") else (f" `{_line(f['path'])}`" if f.get("path") else "")
            out.append(f"- **{f['severity']}** {_line(f['rule_id'])}{loc}: {_line(f['message'])}")
        for k, v in g.items():
            if k not in ("status", "reason", "findings"):
                out.append(f"- {k}: `{json.dumps(v)}`")
        out.append("")
    out += ["## Sent to a model endpoint", ""]
    out += [f"- `{f}`" for f in r["sent_to_model_endpoint"]] or ["Nothing. No gate in this run called a model."]
    out += ["", "## Relaxations", ""]
    out += [f"- {x}" for x in r["relaxations"]] or ["None."]
    missing = r["controls_not_assessed"]
    out += ["", "## Baseline controls not assessed by this run", "",
            f"{len(missing)} of {p['controls']} controls in the baseline were not assessed by any gate in this run. "
            "This tool does not claim them; they belong to the system security plan.", ""]
    if missing:
        out.append(", ".join(missing))
    return "\n".join(out) + "\n"


def write_receipt(run_dir: Path, receipt: dict) -> None:
    check_no_secrets(receipt)
    atomic_write(run_dir / "receipt.json", json.dumps(receipt, indent=1) + "\n")
    atomic_write(run_dir / "receipt.md", render_md(receipt))
