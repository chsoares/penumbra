"""Tests for PS1 .NET Assembly Reflective Loader pass."""

from __future__ import annotations

from penumbra.ps.assembly_loader import Ps1AssemblyLoaderPass
from penumbra.types import PassConfig, PipelineType

# Minimal fake .NET assembly bytes (just needs to be non-empty for generation test)
_FAKE_ASSEMBLY = b"MZ" + b"\x00" * 100 + b"This is test assembly data"


class TestPs1AssemblyLoader:
    def test_generates_ps1_script(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.DOTNET_IL)
        result = Ps1AssemblyLoaderPass().apply(_FAKE_ASSEMBLY, cfg)
        text = result.decode("utf-8")
        stripped = text.replace("'", "").replace("+", "")
        # Should contain key PS1 constructs
        assert "FromBase64String" in text
        assert "DeflateStream" in stripped
        assert "Assembly" in stripped
        assert "EntryPoint" in text

    def test_no_amsi_bypass_inline(self) -> None:
        """AMSI bypass should NOT be inside the loader script.

        It must be placed outside the Base64+IEX block by the encode pass,
        otherwise AMSI detects the bypass pattern before it can execute.
        """
        cfg = PassConfig(pipeline=PipelineType.DOTNET_IL)
        result = Ps1AssemblyLoaderPass().apply(_FAKE_ASSEMBLY, cfg)
        text = result.decode("utf-8")
        assert "VirtualProtect" not in text
        assert "amsiInitFailed" not in text.replace("'", "").replace("+", "")

    def test_is_opt_in(self) -> None:
        assert Ps1AssemblyLoaderPass.opt_in is True

    def test_pass_name(self) -> None:
        assert Ps1AssemblyLoaderPass().name == "ps1-loader"

    def test_randomized_output(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.DOTNET_IL)
        r1 = Ps1AssemblyLoaderPass().apply(_FAKE_ASSEMBLY, cfg).decode("utf-8")
        r2 = Ps1AssemblyLoaderPass().apply(_FAKE_ASSEMBLY, cfg).decode("utf-8")
        # Base64 payload should be the same, but variable names differ
        assert r1 != r2

    def test_compressed_payload_embedded(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.DOTNET_IL)
        result = Ps1AssemblyLoaderPass().apply(_FAKE_ASSEMBLY, cfg)
        text = result.decode("utf-8")
        # Should have a base64 string (compressed assembly)
        import re
        b64_match = re.search(r"'([A-Za-z0-9+/=]{20,})'", text)
        assert b64_match is not None
