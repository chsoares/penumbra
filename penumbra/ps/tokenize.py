"""PS1 string fragmentation pass — splits suspicious keyword strings."""

from __future__ import annotations

import re
import secrets

from penumbra.types import PassConfig

# Keywords that trigger fragmentation (case-insensitive).
_SUSPICIOUS: tuple[str, ...] = (
    "Invoke-Expression",
    "IEX",
    "Invoke-Command",
    "Invoke-WebRequest",
    "DownloadString",
    "DownloadFile",
    "Net.WebClient",
    "Reflection.Assembly",
    "System.Runtime",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "amsi",
    "AmsiUtils",
    "Bypass",
)

_SUSPICIOUS_RE = re.compile(
    "|".join(re.escape(k) for k in _SUSPICIOUS),
    re.IGNORECASE,
)

# Match double-quoted or single-quoted strings.
_STRING_RE = re.compile(r'"(?:[^"\\`]|`.|"")*"|\'(?:[^\']|\'\')*\'')


def _fragment_concat(value: str) -> str:
    """Split *value* into random concatenation pieces."""
    if len(value) < 3:
        return f'"{value}"'
    pieces: list[str] = []
    i = 0
    while i < len(value):
        remaining = len(value) - i
        if remaining <= 3:
            pieces.append(value[i:])
            break
        chunk = secrets.randbelow(min(remaining - 1, 6)) + 2
        pieces.append(value[i : i + chunk])
        i += chunk
    return "(" + "+".join(f'"{p}"' for p in pieces) + ")"


def _fragment_charcode(value: str) -> str:
    """Convert *value* to a char-code array join."""
    codes = ",".join(f"[char]{ord(c)}" for c in value)
    return f"(-join @({codes}))"


def _should_fragment(content: str) -> bool:
    """Return True if the string content contains a suspicious keyword."""
    return bool(_SUSPICIOUS_RE.search(content))


class TokenizePass:
    """Fragment strings containing suspicious keywords via concatenation."""

    @property
    def name(self) -> str:
        return "tokenize"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        source = data.decode("utf-8")

        def _replace(m: re.Match[str]) -> str:
            full = m.group(0)
            inner = full[1:-1]

            if not _should_fragment(inner):
                return full

            # For short high-value strings, randomly use char-code form.
            if len(inner) < 20 and secrets.randbelow(2) == 0:
                return _fragment_charcode(inner)

            # Concatenation form works for both quote styles.
            return _fragment_concat(inner)

        result = _STRING_RE.sub(_replace, source)
        return result.encode("utf-8")
