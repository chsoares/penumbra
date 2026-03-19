"""Auto-detect pipeline type from file content and extension."""

from __future__ import annotations

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
    """Check if MZ binary imports mscoree.dll (managed .NET assembly)."""
    lower = data[:4096].lower()
    return b"mscoree.dll" in lower or b"_corexemain" in lower


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
