"""securebuilderbot_standards — the vendored standards and the checks that keep them honest.

The NIST SP 800-53 Rev 5 catalog and baselines, the DISA STIG index, the OWASP Top 10 lists, OWASP
MASVS and NIST's publication list, read as objects; the citation verifier that holds every document
to them; the versions a receipt records; and the weekly refresh that keeps the vendored copies
current. Depends on nothing but the standard library. Not a gate: core calls `versions()` for the
receipt, and sentinel reads the catalog and the checklists.
"""

from .citations import Citation, Verifier, verify_citations, verify_files
from .data import Control, Masvs, NistPub, OwaspLists, StigRule, baseline, catalog, masvs, nist_pubs, owasp, stigs, versions

__version__ = "0.1.2"
__all__ = [
    "Citation", "Control", "Masvs", "NistPub", "OwaspLists", "StigRule", "Verifier",
    "baseline", "catalog", "masvs", "nist_pubs", "owasp", "stigs", "verify_citations", "verify_files", "versions",
]
