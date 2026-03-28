"""Integration tests for the full PS1 pipeline."""

from __future__ import annotations

import base64
from pathlib import Path

from penumbra.pipeline import resolve_passes, run
from penumbra.types import PassConfig, PipelineType

# Ensure PS1 pipeline is registered.
import penumbra.ps  # noqa: F401

_FIXTURES = Path(__file__).parent / "fixtures"
_CFG = PassConfig(pipeline=PipelineType.PS1)


def test_full_pipeline_all_passes() -> None:
    source = (_FIXTURES / "complex.ps1").read_bytes()
    passes = resolve_passes(PipelineType.PS1)
    result = run(source, passes, _CFG).decode("utf-8")

    # Output should contain obfuscated decoder stub (encode pass ran last).
    stripped = result.replace("'", "").replace("+", "")
    assert "FromBase64String" in stripped
    assert "Expression" in stripped

    # Extract the base64 payload (first quoted string).
    b64_str = result.split("'")[1]
    inner = base64.b64decode(b64_str).decode("utf-8")

    # Original variable names should be gone (rename pass).
    assert "$greeting" not in inner
    assert "$count" not in inner

    # AMSI bypass should be present (inside encoded block for default pipeline).
    assert "[Ref].Assembly" in inner


def test_selective_passes() -> None:
    source = (_FIXTURES / "complex.ps1").read_bytes()
    passes = resolve_passes(PipelineType.PS1, ["rename", "encode"])
    result = run(source, passes, _CFG).decode("utf-8")

    stripped = result.replace("'", "").replace("+", "")
    assert "FromBase64String" in stripped

    # Decode inner layer.
    b64_str = result.split("'")[1]
    inner = base64.b64decode(b64_str).decode("utf-8")

    # Renamed but no AMSI bypass.
    assert "$greeting" not in inner
    assert "[Ref].Assembly" not in inner
