"""The QA gate: do the tests prove the code, including the security controls? (PRD § The three gates)

Core finds this module by name (runner.py:GATE_MODULES) and calls GATE() for the gate.
"""

from __future__ import annotations

__version__ = "0.1.1"


def GATE():  # upper-case by contract: core looks this name up (runner.py:discover_gate)
    from .gate import QaGate
    return QaGate()
