"""Tests for PS1 AMSI bypass techniques."""

from __future__ import annotations

import pytest

from penumbra.ps.amsi import AmsiBypassPass
from penumbra.types import PassConfig, PipelineType

_CONFIG = PassConfig(pipeline=PipelineType.PS1)
_SCRIPT = b"Write-Host 'hello'"


def _strip_concat(text: str) -> str:
    """Remove string concatenation artifacts to check logical content."""
    return text.replace("'", "").replace("+", "").replace('"', "")


class TestReflectionBypass:
    def test_default_is_reflection(self) -> None:
        result = AmsiBypassPass().apply(_SCRIPT, _CONFIG)
        text = result.decode("utf-8")
        assert "amsiInitFailed" in _strip_concat(text)
        assert "Write-Host" in text

    def test_explicit_reflection(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"amsi_technique": "reflection"})
        result = AmsiBypassPass().apply(_SCRIPT, cfg)
        text = result.decode("utf-8")
        assert "amsiInitFailed" in _strip_concat(text)


class TestPatchBypass:
    def test_patch_generates_valid_ps1(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"amsi_technique": "patch"})
        result = AmsiBypassPass().apply(_SCRIPT, cfg)
        text = result.decode("utf-8")
        assert "VirtualProtect" in text
        assert "0xB8" in text
        assert "0xC3" in text
        assert "Add-Type" in text
        assert "Write-Host" in text

    def test_patch_has_randomized_names(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"amsi_technique": "patch"})
        r1 = AmsiBypassPass().apply(_SCRIPT, cfg).decode("utf-8")
        r2 = AmsiBypassPass().apply(_SCRIPT, cfg).decode("utf-8")
        assert r1 != r2


class TestContextBypass:
    def test_context_generates_valid_ps1(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"amsi_technique": "context"})
        result = AmsiBypassPass().apply(_SCRIPT, cfg)
        text = result.decode("utf-8")
        assert "AllocHGlobal" in text
        assert "amsiContext" in _strip_concat(text)
        assert "Write-Host" in text


class TestInvalidTechnique:
    def test_unknown_technique_raises(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"amsi_technique": "invalid"})
        with pytest.raises(ValueError, match="Unknown AMSI technique"):
            AmsiBypassPass().apply(_SCRIPT, cfg)
