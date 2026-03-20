"""Tests for penumbra.ps.tokenize."""

from __future__ import annotations

from penumbra.ps.tokenize import TokenizePass
from penumbra.types import Pass, PassConfig, PipelineType

_CFG = PassConfig(pipeline=PipelineType.PS1)


def test_tokenize_pass_name() -> None:
    assert TokenizePass().name == "tokenize"


def test_fragments_suspicious_string() -> None:
    source = b'$cmd = "Invoke-Expression"\n'
    result = TokenizePass().apply(source, _CFG).decode("utf-8")
    # The full keyword should no longer appear as a single token.
    assert '"Invoke-Expression"' not in result
    # Should contain concatenation or char-code markers.
    assert "+" in result or "[char]" in result


def test_ignores_benign_strings() -> None:
    source = b'$msg = "Hello World"\n'
    result = TokenizePass().apply(source, _CFG).decode("utf-8")
    assert '"Hello World"' in result


def test_satisfies_protocol() -> None:
    assert isinstance(TokenizePass(), Pass)
