"""A small index set shaped like the self-test's fixtures, written into a directory on request."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VENDORED = ROOT / "standards" / "data" / "controls"

SMALL_NIST = {
    "_catalog_version": "5.2.0", "_retrieved": "2026-09-19", "_source": "https://example.invalid/catalog.json",
    "controls": {
        "AC-2": {"t": "Account Management", "s": "active"},
        "AC-3": {"t": "Access Enforcement", "s": "active"},
        "CM-6": {"t": "Configuration Settings", "s": "active"},
        "SC-7": {"t": "Boundary Protection", "s": "active"},
        "SC-7(3)": {"t": "Access Points", "s": "active"},
        "SA-12": {"t": "Supply Chain Protection", "s": "withdrawn", "into": ["SR"]},
    },
}
SMALL_BASELINES = {
    "_catalog_version": "5.2.0", "_retrieved": "2026-10-15",
    "moderate": ["AC-2", "AC-3", "SC-7"], "high": ["AC-2", "AC-3", "SC-7", "SC-7(3)"],
}
SMALL_OWASP = {
    "_retrieved": "2026-09-19",
    "web": {"current": "2025", "editions": {"2021": {"A02": "Cryptographic Failures"},
                                             "2025": {"A01": "Broken Access Control", "A02": "Security Misconfiguration",
                                                      "A04": "Cryptographic Failures"}}},
    "llm": {"current": "2025", "editions": {"2025": {"LLM01": "Prompt Injection", "LLM06": "Excessive Agency",
                                                      "LLM08": "Vector And Embedding Weaknesses"}}},
}
SMALL_STIG = {
    "_retrieved": "2026-09-19",
    "rules": {"RHEL-08-010000": {"t": "a", "s": "disa-stig-rhel8-v2r8"},
              "SRG-APP-000001-AS-000001": {"t": "b", "s": "disa-stig-srg-app-v2r1"}},
    "sources": {"disa-stig-rhel8-v2r8": 1, "disa-stig-srg-app-v2r1": 1},
}
SMALL_MASVS = {
    "_retrieved": "2026-09-19", "_latest_release": "v2.1.0",
    "groups": {"MASVS-NETWORK": "Network Communication", "MASVS-STORAGE": "Storage"},
    "controls": {"MASVS-NETWORK-1": "The app secures all network traffic.", "MASVS-STORAGE-1": "The app securely stores sensitive data."},
}
SMALL_PUBS = {
    "_retrieved": "2026-09-19",
    "pubs": {"SP 800-163": {"revisions": ["", "r1"], "drafts": [], "latest": "r1"},
             "SP 800-124": {"revisions": ["", "r1", "r2"], "drafts": ["r3.ipd"], "latest": "r2"},
             "FIPS 140-3": {"revisions": [""], "drafts": [], "latest": ""}},
}
FILES = {
    "nist-800-53r5-index.json": SMALL_NIST, "nist-800-53r5-baselines.json": SMALL_BASELINES,
    "owasp-index.json": SMALL_OWASP, "stig-index.json": SMALL_STIG,
    "masvs-index.json": SMALL_MASVS, "nist-pubs-index.json": SMALL_PUBS,
}


def write_indexes(where: Path, only: set[str] | None = None) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    for name, doc in FILES.items():
        if only is None or name in only:
            (where / name).write_text(json.dumps(doc))
    return where

