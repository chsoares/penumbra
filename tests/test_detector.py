"""Tests for penumbra.detector."""

from __future__ import annotations

from pathlib import Path

import pytest

from penumbra.detector import detect
from penumbra.types import PipelineType


def test_detect_ps1_by_extension(hello_ps1: Path) -> None:
    assert detect(hello_ps1) == PipelineType.PS1


def test_detect_script_by_extension(tmp_path: Path) -> None:
    py_file = tmp_path / "test.py"
    py_file.write_text("print('hello')")
    assert detect(py_file) == PipelineType.SCRIPT

    sh_file = tmp_path / "test.sh"
    sh_file.write_text("echo hello")
    assert detect(sh_file) == PipelineType.SCRIPT


def test_detect_shebang_python(tmp_path: Path) -> None:
    script = tmp_path / "noext"
    script.write_bytes(b"#!/usr/bin/env python3\nprint('hi')\n")
    assert detect(script) == PipelineType.SCRIPT


def test_detect_shebang_bash(tmp_path: Path) -> None:
    script = tmp_path / "noext"
    script.write_bytes(b"#!/bin/bash\necho hi\n")
    assert detect(script) == PipelineType.SCRIPT


def test_detect_mz_dotnet(tmp_path: Path) -> None:
    """MZ header with mscoree.dll marker → DOTNET_IL."""
    fake_pe = b"MZ" + b"\x00" * 100 + b"mscoree.dll" + b"\x00" * 100
    f = tmp_path / "test.exe"
    f.write_bytes(fake_pe)
    assert detect(f) == PipelineType.DOTNET_IL


def test_detect_mz_native_pe(tmp_path: Path) -> None:
    """MZ header without .NET markers → PE."""
    fake_pe = b"MZ" + b"\x00" * 200
    f = tmp_path / "test.exe"
    f.write_bytes(fake_pe)
    assert detect(f) == PipelineType.PE


def test_detect_unknown_raises(tmp_path: Path) -> None:
    unknown = tmp_path / "data.bin"
    unknown.write_bytes(b"\x00\x01\x02\x03")
    with pytest.raises(ValueError, match="Cannot detect"):
        detect(unknown)
