"""Tests for VBS pipeline passes."""

from __future__ import annotations

from penumbra.vbs.encode import VbsEncodePass
from penumbra.vbs.wrap import VbsWrapPass
from penumbra.types import PassConfig, PipelineType

_CONFIG = PassConfig(pipeline=PipelineType.VBS)
_SCRIPT = b'MsgBox "Hello World"'


class TestVbsEncode:
    def test_generates_xor_decoder(self) -> None:
        result = VbsEncodePass().apply(_SCRIPT, _CONFIG)
        text = result.decode("utf-8")
        assert "Xor" in text
        assert "Execute" in text
        assert "For" in text
        assert "Mid(" in text

    def test_pass_name(self) -> None:
        assert VbsEncodePass().name == "encode"

    def test_randomized_variables(self) -> None:
        r1 = VbsEncodePass().apply(_SCRIPT, _CONFIG).decode("utf-8")
        r2 = VbsEncodePass().apply(_SCRIPT, _CONFIG).decode("utf-8")
        # Different runs produce different variable names
        assert r1 != r2


class TestVbsWrap:
    def test_adds_wscript_shell(self) -> None:
        result = VbsWrapPass().apply(_SCRIPT, _CONFIG)
        text = result.decode("utf-8")
        assert "WScript.Shell" in text
        assert "CreateObject" in text

    def test_preserves_original_content(self) -> None:
        result = VbsWrapPass().apply(_SCRIPT, _CONFIG)
        text = result.decode("utf-8")
        assert 'MsgBox "Hello World"' in text

    def test_pass_name(self) -> None:
        assert VbsWrapPass().name == "wrap"


class TestVbsPipeline:
    def test_encode_then_wrap(self) -> None:
        """Test the full pipeline: encode → wrap."""
        encoded = VbsEncodePass().apply(_SCRIPT, _CONFIG)
        wrapped = VbsWrapPass().apply(encoded, _CONFIG)
        text = wrapped.decode("utf-8")
        assert "WScript.Shell" in text
        assert "Xor" in text
        assert "Execute" in text
