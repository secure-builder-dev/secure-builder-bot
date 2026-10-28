#!/usr/bin/env python3
"""build-owasp-index.py — vendored index of the OWASP lists the engine cites.

WHY THIS EXISTS
  OWASP renumbers between editions. Excessive agency was LLM08 in 2023 and is LLM06 in 2025;
  Cryptographic Failures was A02 in 2021 and is A04 in 2025. An unversioned citation silently
  becomes wrong when the list moves, and no catalogue check catches it because every identifier
  still "exists" — it just means something else now. That defect shipped here and sat for months.

  This index carries EVERY edition the engine might cite, not just the current one, so
  verify-citations can say "A02 is Cryptographic Failures in 2021 and Security Misconfiguration in
  2025 — which edition is this document written against?" instead of shrugging.

SOURCES (primary; both are the OWASP projects' own repositories)
  web : github.com/OWASP/Top10                 — <edition>/mkdocs.yml `nav:` is the authoritative
                                                 ordered list, maintained by the project itself
  llm : github.com/OWASP/www-project-top-10-for-large-language-model-applications
                                              — 2_0_vulns/LLMnn_Name.md filenames carry id + title

USAGE
    git clone --depth 1 https://github.com/OWASP/Top10.git /tmp/t10
    git clone --depth 1 https://github.com/OWASP/www-project-top-10-for-large-language-model-applications.git /tmp/llm
    python3 standards/scripts/build-owasp-index.py /tmp/t10 /tmp/llm \\
        standards/data/controls/owasp-index.json

  `make refresh-frameworks` does this for you.
"""
import datetime
import json
import os
import re
import subprocess
import sys

NAV = re.compile(r"^\s+-\s+(A\d{2})\s+(.+?):\s*'.*?'\s*$")
LLM = re.compile(r"^(LLM\d{2})_(.+)\.md$")


def split_camel(name):
    """SensitiveInformationDisclosure -> Sensitive Information Disclosure"""
    return re.sub(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", name).strip()


def web_editions(repo):
    """Every edition directory that ships an mkdocs.yml with a Top 10 nav."""
    out = {}
    for entry in sorted(os.listdir(repo)):
        cfg = os.path.join(repo, entry, "mkdocs.yml")
        if not (entry.isdigit() and os.path.isfile(cfg)):
            continue
        items = {}
        for line in open(cfg, encoding="utf-8", errors="replace"):
            m = NAV.match(line)
            if m:
                items[m.group(1)] = m.group(2).strip()
        if items:
            out[entry] = items
    return out


def llm_editions(repo):
    """2_0_vulns is the 2025 list. Older editions live in differently named directories."""
    out = {}
    for d, edition in (("2_0_vulns", "2025"), ("1_1_vulns", "2023")):
        path = os.path.join(repo, d)
        if not os.path.isdir(path):
            continue
        items = {}
        for fn in sorted(os.listdir(path)):
            m = LLM.match(fn)
            if m and m.group(1) != "LLM00":
                items[m.group(1)] = split_camel(m.group(2))
        if items:
            out[edition] = items
    return out


def head(repo):
    try:
        return subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=20).stdout.strip()[:12]
    except Exception:
        return ""


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: build-owasp-index.py <Top10-repo> <llm-repo> <out.json>")
    t10, llm, out = sys.argv[1], sys.argv[2], sys.argv[3]

    web, lm = web_editions(t10), llm_editions(llm)
    if not web or not lm:
        sys.exit("build-owasp-index: no editions parsed — check the repository paths")

    doc = {
        "_retrieved": datetime.date.today().isoformat(),
        "_generator": "standards/scripts/build-owasp-index.py",
        "_sources": {
            "web": {"repo": "https://github.com/OWASP/Top10",
                    "commit": head(t10), "parsed_from": "<edition>/mkdocs.yml nav"},
            "llm": {"repo": "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications",
                    "commit": head(llm), "parsed_from": "2_0_vulns/ filenames"},
        },
        "web": {"current": max(web), "editions": web},
        "llm": {"current": max(lm), "editions": lm},
    }
    json.dump(doc, open(out, "w"), indent=1, sort_keys=True)
    print(f"{out}: web editions {sorted(web)} (current {max(web)}), "
          f"llm editions {sorted(lm)} (current {max(lm)}), {os.path.getsize(out)//1024} KB")


if __name__ == "__main__":
    main()
