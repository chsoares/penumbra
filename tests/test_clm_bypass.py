"""Tests for CLM bypass pass — verify C# project generation."""

from __future__ import annotations

import tempfile
from pathlib import Path

from penumbra.dotnet._loader_utils import encrypt_and_encode, xor_encrypt
from penumbra.dotnet.clm_bypass import ClmBypassPass, _generate_clm_project
from penumbra.types import PassConfig, PipelineType

_FAKE_PS1 = b"Write-Host 'Hello from FullLanguage mode'"
_CONFIG = PassConfig(pipeline=PipelineType.PS1)


class TestClmProject:
    def test_generates_csproj(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_PS1)
        with tempfile.TemporaryDirectory() as td:
            _generate_clm_project(payload_b64, key_b64, Path(td))
            csproj = (Path(td) / "Loader.csproj").read_text()
            assert "net472" in csproj
            assert "System.Management.Automation" in csproj
            assert "Exe" in csproj

    def test_generates_program_with_runspace(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_PS1)
        with tempfile.TemporaryDirectory() as td:
            _generate_clm_project(payload_b64, key_b64, Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "RunspaceFactory.CreateRunspace" in prog
            assert "PowerShell.Create" in prog
            assert "AddScript" in prog
            assert "Invoke" in prog

    def test_supports_argv_mode(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_PS1)
        with tempfile.TemporaryDirectory() as td:
            _generate_clm_project(payload_b64, key_b64, Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "args.Length" in prog
            assert "FromBase64String(args[0])" in prog

    def test_generates_junk_files(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_PS1)
        with tempfile.TemporaryDirectory() as td:
            _generate_clm_project(payload_b64, key_b64, Path(td))
            modules = list(Path(td).glob("Module*.cs"))
            assert len(modules) >= 3


class TestClmBypassPass:
    def test_is_opt_in(self) -> None:
        assert ClmBypassPass.opt_in is True

    def test_pass_name(self) -> None:
        assert ClmBypassPass().name == "clm-bypass"
