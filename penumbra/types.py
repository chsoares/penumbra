"""Core types for Penumbra's composable pass architecture."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class PipelineType(Enum):
    """Supported obfuscation pipeline types."""

    PS1 = "ps"
    DOTNET_IL = "dotnet-il"
    SCRIPT = "script"
    PE = "pe"
    SHELLCODE = "shellcode"
    VBS = "vbs"


@dataclass(frozen=True)
class PassConfig:
    """Immutable configuration passed to every obfuscation pass."""

    pipeline: PipelineType
    safe_rename: bool = False
    verbose: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Pass(Protocol):
    """Protocol that all obfuscation passes must satisfy.

    Passes are stateless and pure: apply(input, config) -> output.
    """

    @property
    def name(self) -> str: ...

    def apply(self, data: bytes, config: PassConfig) -> bytes: ...
