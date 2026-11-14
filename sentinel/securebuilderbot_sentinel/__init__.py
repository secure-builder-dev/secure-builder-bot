"""The Sentinel gate: a cold reviewer running the profile's NIST 800-53 checklist on the diff
(docs/PRD.md § The three gates). Core finds this module by name (runner.py:GATE_MODULES)."""

from __future__ import annotations

__version__ = "0.1.2"


def GATE():  # upper-case by contract: core looks this name up (runner.py:discover_gate)
    from .gate import SentinelGate
    return SentinelGate()
