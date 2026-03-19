"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture()
def hello_ps1() -> Path:
    return FIXTURES_DIR / "hello.ps1"


@pytest.fixture()
def hello_ps1_bytes() -> bytes:
    return (FIXTURES_DIR / "hello.ps1").read_bytes()
