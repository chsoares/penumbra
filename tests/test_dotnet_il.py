"""Tests for penumbra.dotnet IL obfuscation pipeline."""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from penumbra.dotnet.il_worker import (
    DotnetEncryptStringsPass,
    DotnetFlowPass,
    DotnetRenamePass,
    DotnetScrubGuidPass,
    DotnetStripDebugPass,
)
from penumbra.types import Pass, PassConfig, PipelineType

_needs_dotnet = pytest.mark.skipif(
    not shutil.which("dotnet"), reason="dotnet SDK not installed"
)


def test_dotnet_rename_pass_name() -> None:
    assert DotnetRenamePass().name == "rename"


def test_dotnet_encrypt_strings_pass_name() -> None:
    assert DotnetEncryptStringsPass().name == "encrypt-strings"


def test_dotnet_flow_pass_name() -> None:
    assert DotnetFlowPass().name == "flow"


def test_dotnet_strip_debug_pass_name() -> None:
    assert DotnetStripDebugPass().name == "strip-debug"


def test_dotnet_scrub_guid_pass_name() -> None:
    assert DotnetScrubGuidPass().name == "scrub-guid"


def test_all_passes_satisfy_protocol() -> None:
    passes = [
        DotnetRenamePass(),
        DotnetEncryptStringsPass(),
        DotnetFlowPass(),
        DotnetStripDebugPass(),
        DotnetScrubGuidPass(),
    ]
    for p in passes:
        assert isinstance(p, Pass), f"{p.name} does not satisfy Pass protocol"


@_needs_dotnet
def test_worker_invocation_with_real_assembly(tmp_path: Path) -> None:
    """Compile a minimal C# project, run rename pass, verify output is valid PE."""
    proj_dir = tmp_path / "TestApp"
    proj_dir.mkdir()

    csproj = proj_dir / "TestApp.csproj"
    csproj.write_text(textwrap.dedent("""\
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup>
            <OutputType>Exe</OutputType>
            <TargetFramework>net8.0</TargetFramework>
            <ImplicitUsings>enable</ImplicitUsings>
          </PropertyGroup>
        </Project>
    """))

    program_cs = proj_dir / "Program.cs"
    program_cs.write_text(textwrap.dedent("""\
        using System;
        Console.WriteLine("Hello from test assembly");
    """))

    # Build the project
    build_result = subprocess.run(
        ["dotnet", "build", str(proj_dir), "-c", "Release", "-o", str(tmp_path / "out")],
        capture_output=True,
    )
    assert build_result.returncode == 0, (
        f"dotnet build failed: {build_result.stderr.decode()}"
    )

    dll_path = tmp_path / "out" / "TestApp.dll"
    assert dll_path.exists(), "Compiled DLL not found"

    data = dll_path.read_bytes()
    config = PassConfig(pipeline=PipelineType.DOTNET_IL)
    result = DotnetRenamePass().apply(data, config)

    # Verify output is a valid PE (starts with MZ)
    assert result[:2] == b"MZ", "Output is not a valid PE file"
    assert len(result) > 0


def test_missing_dotnet_raises_with_mock() -> None:
    """Test that missing dotnet raises RuntimeError using mock."""
    config = PassConfig(pipeline=PipelineType.DOTNET_IL)
    with patch("penumbra.dotnet.il_worker.shutil.which", return_value=None):
        with pytest.raises(RuntimeError, match="dotnet SDK not found"):
            DotnetRenamePass().apply(b"dummy", config)
