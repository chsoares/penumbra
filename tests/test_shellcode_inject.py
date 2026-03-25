"""Tests for shellcode process injection pass — verify project generation."""

from __future__ import annotations

import tempfile
from pathlib import Path

from penumbra.shellcode.inject import ShellcodeInjectPass, _generate_inject_project
from penumbra.types import PassConfig, PipelineType

# Fake encrypted shellcode: key(32) + iv(16) + ciphertext
_FAKE_ENCRYPTED = b"\x00" * 32 + b"\x01" * 16 + b"\x02" * 64
_CONFIG = PassConfig(pipeline=PipelineType.SHELLCODE)


class TestInjectProject:
    def test_generates_csproj(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _generate_inject_project("AAAA", "BBBB", "CCCC", "notepad.exe", Path(td))
            csproj = (Path(td) / "Loader.csproj").read_text()
            assert "net472" in csproj
            assert "WinExe" in csproj

    def test_generates_program_with_injection_apis(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _generate_inject_project("AAAA", "BBBB", "CCCC", "notepad.exe", Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "VirtualAllocEx" in prog
            assert "WriteProcessMemory" in prog
            assert "VirtualProtectEx" in prog
            assert "CreateRemoteThread" in prog
            assert "notepad.exe" in prog

    def test_custom_target_process(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _generate_inject_project("AAAA", "BBBB", "CCCC", "explorer.exe", Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "explorer.exe" in prog

    def test_generates_amsi_bypass(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _generate_inject_project("AAAA", "BBBB", "CCCC", "notepad.exe", Path(td))
            assert (Path(td) / "AmsiBypass.cs").exists()

    def test_generates_junk_files(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            _generate_inject_project("AAAA", "BBBB", "CCCC", "notepad.exe", Path(td))
            modules = list(Path(td).glob("Module*.cs"))
            assert len(modules) >= 5


class TestShellcodeInjectPass:
    def test_is_opt_in(self) -> None:
        assert ShellcodeInjectPass.opt_in is True

    def test_pass_name(self) -> None:
        assert ShellcodeInjectPass().name == "inject"

    def test_rejects_short_input(self) -> None:
        import pytest
        with pytest.raises(ValueError, match="too short"):
            ShellcodeInjectPass().apply(b"\x00" * 10, _CONFIG)
