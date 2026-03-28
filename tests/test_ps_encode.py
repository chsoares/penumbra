"""Tests for penumbra.ps.encode."""

from __future__ import annotations

import base64
from pathlib import Path

from penumbra.ps.encode import Base64EncodePass
from penumbra.types import PassConfig, PipelineType


def test_output_contains_decoder_keywords(hello_ps1_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.PS1)
    result = Base64EncodePass().apply(hello_ps1_bytes, config)
    text = result.decode("utf-8")
    # Method names are split for evasion: ('FromB'+'ase64S'+'tring')
    stripped = text.replace("'", "").replace("+", "")
    assert "FromBase64String" in stripped
    assert "Expression" in stripped


def test_base64_is_reversible(hello_ps1_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.PS1)
    result = Base64EncodePass().apply(hello_ps1_bytes, config)
    text = result.decode("utf-8")
    # Extract the Base64 string between single quotes
    b64_str = text.split("'")[1]
    decoded = base64.b64decode(b64_str)
    assert decoded == hello_ps1_bytes


def test_encode_pass_name() -> None:
    assert Base64EncodePass().name == "encode"
