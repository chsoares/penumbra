"""Tests for penumbra.ps.amsi."""

from __future__ import annotations

from penumbra.ps.amsi import AmsiBypassPass
from penumbra.types import Pass, PassConfig, PipelineType

_CFG = PassConfig(pipeline=PipelineType.PS1)


def test_amsi_pass_name() -> None:
    assert AmsiBypassPass().name == "amsi"


def test_prepends_bypass_code() -> None:
    source = b"Write-Host 'hello'\n"
    result = AmsiBypassPass().apply(source, _CFG).decode("utf-8")
    # Bypass code appears before the original script.
    assert result.index("[Ref].Assembly") < result.index("Write-Host")


def test_bypass_has_no_plain_amsi_strings() -> None:
    source = b"Write-Host 'test'\n"
    result = AmsiBypassPass().apply(source, _CFG).decode("utf-8")
    # The bypass must not contain the full plain strings.
    bypass_section = result[: result.index("Write-Host")]
    assert "AmsiUtils" not in bypass_section
    assert "amsiInitFailed" not in bypass_section


def test_original_script_preserved_after_bypass() -> None:
    source = b"Write-Host 'hello'\n"
    result = AmsiBypassPass().apply(source, _CFG).decode("utf-8")
    assert result.endswith("Write-Host 'hello'\n")


def test_satisfies_protocol() -> None:
    assert isinstance(AmsiBypassPass(), Pass)
