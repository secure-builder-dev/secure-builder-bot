"""The scanners module: the scanner wrappers and pins, the CVE-freshness check, per-scanner receipts
and the Scan gate. Core finds it by name (securebuilderbot_core.runner.discover_gate)."""

from .gate import ScanGate

GATE = ScanGate
__all__ = ["GATE", "ScanGate"]
