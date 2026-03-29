"""Tests for LOLBAS passes — verify C# project generation."""

from __future__ import annotations

import tempfile
from pathlib import Path

from penumbra.dotnet._loader_utils import encrypt_and_encode
from penumbra.dotnet.lolbas import (
    InstallUtilPass,
    RegAsmPass,
    _generate_installutil_project,
    _generate_regasm_project,
)
from penumbra.types import PassConfig, PipelineType

_FAKE_ASSEMBLY = b"MZ" + b"\x00" * 100 + b"test payload data"
_CONFIG = PassConfig(pipeline=PipelineType.DOTNET_IL)


class TestInstallUtilProject:
    def test_generates_csproj(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_installutil_project(payload_b64, key_b64, Path(td))
            csproj = (Path(td) / "Loader.csproj").read_text()
            assert "net472" in csproj
            assert "System.Configuration.Install" in csproj
            assert "Exe" in csproj

    def test_generates_program_cs(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_installutil_project(payload_b64, key_b64, Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "RunInstaller(true)" in prog
            assert "Installer" in prog
            assert "Uninstall" in prog
            assert "Assembly.Load" in prog

    def test_pass_is_opt_in(self) -> None:
        assert InstallUtilPass.opt_in is True

    def test_pass_name(self) -> None:
        assert InstallUtilPass().name == "lolbas-installutil"


class TestRegAsmProject:
    def test_generates_csproj(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_regasm_project(payload_b64, key_b64, Path(td))
            csproj = (Path(td) / "Loader.csproj").read_text()
            assert "Library" in csproj
            assert "net472" in csproj

    def test_generates_program_cs(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_regasm_project(payload_b64, key_b64, Path(td))
            prog = (Path(td) / "Program.cs").read_text()
            assert "ComVisible(true)" in prog
            assert "Guid" in prog
            assert "ComUnregisterFunction" in prog
            assert "Assembly.Load" in prog

    def test_pass_is_opt_in(self) -> None:
        assert RegAsmPass.opt_in is True

    def test_pass_name(self) -> None:
        assert RegAsmPass().name == "lolbas-regasm"


class TestFragmentAndJunkGeneration:
    def test_generates_fragment_files(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_installutil_project(payload_b64, key_b64, Path(td))
            fragments = list(Path(td).glob("Fragment*.cs"))
            assert len(fragments) >= 1

    def test_generates_junk_files(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_installutil_project(payload_b64, key_b64, Path(td))
            modules = list(Path(td).glob("Module*.cs"))
            assert len(modules) >= 5

    def test_generates_amsi_bypass(self) -> None:
        payload_b64, key_b64 = encrypt_and_encode(_FAKE_ASSEMBLY)
        with tempfile.TemporaryDirectory() as td:
            _generate_installutil_project(payload_b64, key_b64, Path(td))
            assert (Path(td) / "AmsiBypass.cs").exists()
