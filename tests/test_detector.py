"""Tests for penumbra.detector."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from penumbra.detector import detect
from penumbra.types import PipelineType


def _make_pe(dotnet: bool = False) -> bytes:
    """Build a minimal valid PE with optional CLR data directory."""
    # MZ header (64 bytes min, PE offset at 0x3C)
    mz = bytearray(128)
    mz[0:2] = b"MZ"
    pe_offset = 64
    struct.pack_into("<I", mz, 0x3C, pe_offset)

    # PE signature
    pe_sig = b"PE\x00\x00"

    # COFF header (20 bytes) — minimal
    coff = bytearray(20)

    # Optional header — PE32 (magic 0x10B)
    # We need at least 208 + 8 = 216 bytes for CLR data dir entry #14
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)  # PE32 magic

    if dotnet:
        # CLR Runtime Header data directory (entry #14, offset 208)
        struct.pack_into("<II", opt, 208, 0x2000, 72)  # VA=0x2000, Size=72

    mz[pe_offset:pe_offset] = pe_sig + bytes(coff) + bytes(opt)
    return bytes(mz)


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
    """MZ+PE with CLR data directory → DOTNET_IL."""
    f = tmp_path / "test.exe"
    f.write_bytes(_make_pe(dotnet=True))
    assert detect(f) == PipelineType.DOTNET_IL


def test_detect_mz_native_pe(tmp_path: Path) -> None:
    """MZ+PE without CLR data directory → PE."""
    f = tmp_path / "test.exe"
    f.write_bytes(_make_pe(dotnet=False))
    assert detect(f) == PipelineType.PE


def test_detect_unknown_raises(tmp_path: Path) -> None:
    unknown = tmp_path / "data.dat"
    unknown.write_bytes(b"\x00\x01\x02\x03")
    with pytest.raises(ValueError, match="Cannot detect"):
        detect(unknown)
