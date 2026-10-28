"""Fixtures: the vendored indexes as they are, and a small index set (smallindex.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from smallindex import VENDORED, write_indexes


@pytest.fixture
def small(tmp_path: Path) -> Path:
    """A complete, tiny index set."""
    return write_indexes(tmp_path / "controls")


@pytest.fixture
def vendored() -> Path:
    return VENDORED
