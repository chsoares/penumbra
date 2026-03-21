"""Auto-detect pipeline type from file content and extension."""

from __future__ import annotations

import struct
from pathlib import Path

from penumbra.types import PipelineType

_EXTENSION_MAP: dict[str, PipelineType] = {
    ".ps1": PipelineType.PS1,
    ".psm1": PipelineType.PS1,
    ".psd1": PipelineType.PS1,
    ".py": PipelineType.SCRIPT,
    ".sh": PipelineType.SCRIPT,
    ".bash": PipelineType.SCRIPT,
}

_SHEBANG_MAP: dict[str, PipelineType] = {
    "python": PipelineType.SCRIPT,
    "bash": PipelineType.SCRIPT,
    "sh": PipelineType.SCRIPT,
    "pwsh": PipelineType.PS1,
    "powershell": PipelineType.PS1,
}


def _check_dotnet_il(data: bytes) -> bool:
    """Check if MZ binary is a .NET assembly by reading the PE CLR data directory.

    A .NET assembly has a non-zero CLR Runtime Header entry (index 14) in the
    PE optional header's data directory table.
    """
    if len(data) < 64:
        return False

    # PE signature offset is at MZ+0x3C
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 24 > len(data):
        return False

    # Verify PE signature "PE\0\0"
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return False

    # Optional header magic (offset pe+24): 0x10B = PE32, 0x20B = PE32+
    opt_offset = pe_offset + 24
    if opt_offset + 2 > len(data):
        return False
    magic = struct.unpack_from("<H", data, opt_offset)[0]

    # CLR Runtime Header is data directory entry #14 (0-indexed)
    # Each entry is 8 bytes (VA + Size). Offset from start of optional header:
    #   PE32:  96 + 14*8 = 208 bytes from opt_offset
    #   PE32+: 112 + 14*8 = 224 bytes from opt_offset
    if magic == 0x10B:
        clr_dir_offset = opt_offset + 208
    elif magic == 0x20B:
        clr_dir_offset = opt_offset + 224
    else:
        return False

    if clr_dir_offset + 8 > len(data):
        return False

    clr_va: int
    clr_size: int
    clr_va, clr_size = struct.unpack_from("<II", data, clr_dir_offset)
    return clr_va != 0 and clr_size != 0


def detect(path: Path, data: bytes | None = None) -> PipelineType:
    """Detect the pipeline type for a given file.

    Priority:
    1. Magic bytes (MZ header → check for .NET IL markers)
    2. Extension map
    3. Shebang heuristic
    4. Raise ValueError if unknown
    """
    if data is None:
        data = path.read_bytes()

    # 1. MZ header — binary file
    if data[:2] == b"MZ":
        if _check_dotnet_il(data):
            return PipelineType.DOTNET_IL
        return PipelineType.PE

    # 2. Extension map
    ext = path.suffix.lower()
    if ext in _EXTENSION_MAP:
        return _EXTENSION_MAP[ext]

    # 3. Shebang heuristic
    if data[:2] == b"#!":
        first_line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace")
        for keyword, pipeline in _SHEBANG_MAP.items():
            if keyword in first_line:
                return pipeline

    raise ValueError(f"Cannot detect pipeline type for '{path.name}'. Use --pipeline to specify.")
