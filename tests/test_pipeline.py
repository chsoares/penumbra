"""Tests for penumbra.pipeline."""

from __future__ import annotations

from penumbra.pipeline import register_pipeline, resolve_passes, run
from penumbra.types import Pass, PassConfig, PipelineType

import pytest


class UpperPass:
    @property
    def name(self) -> str:
        return "upper"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return data.upper()


class ReversePass:
    @property
    def name(self) -> str:
        return "reverse"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return data[::-1]


@pytest.fixture(autouse=True)
def _register_test_passes() -> None:
    register_pipeline(PipelineType.SCRIPT, [UpperPass(), ReversePass()])


def test_resolve_all_passes() -> None:
    passes = resolve_passes(PipelineType.SCRIPT)
    assert [p.name for p in passes] == ["upper", "reverse"]


def test_resolve_specific_passes() -> None:
    passes = resolve_passes(PipelineType.SCRIPT, ["reverse"])
    assert [p.name for p in passes] == ["reverse"]


def test_resolve_unknown_pass_raises() -> None:
    with pytest.raises(ValueError, match="Unknown pass 'nope'"):
        resolve_passes(PipelineType.SCRIPT, ["nope"])


def test_run_chains_passes() -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    passes = resolve_passes(PipelineType.SCRIPT)
    result = run(b"hello", passes, config)
    # upper → HELLO, then reverse → OLLEH
    assert result == b"OLLEH"


def test_run_empty_passes_returns_input() -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = run(b"untouched", [], config)
    assert result == b"untouched"


def test_mock_passes_satisfy_protocol() -> None:
    assert isinstance(UpperPass(), Pass)
    assert isinstance(ReversePass(), Pass)
