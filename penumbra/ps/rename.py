"""PS1 variable and function rename pass — replaces user-defined names with random IDs."""

from __future__ import annotations

import re
import secrets
from typing import NamedTuple

from penumbra.types import PassConfig

# Built-in PS variables to skip (case-insensitive, stored lowercase without $).
_BUILTIN_VARS: frozenset[str] = frozenset(
    v.lower()
    for v in [
        "true",
        "false",
        "null",
        "_",
        "args",
        "PSVersionTable",
        "env",
        "Host",
        "Error",
        "input",
        "PSScriptRoot",
        "PSCommandPath",
        "MyInvocation",
        "this",
        "PSBoundParameters",
        "PID",
        "PWD",
        "HOME",
        "Profile",
        "LASTEXITCODE",
        "?",
        "^",
        "$",
        "Matches",
        "OFS",
        "FormatEnumerationLimit",
        "ConfirmPreference",
        "ErrorActionPreference",
        "VerbosePreference",
        "WarningPreference",
        "DebugPreference",
        "InformationPreference",
        "ProgressPreference",
    ]
)

# Pattern for PS variable references: $identifier (letter/underscore start).
_VAR_RE = re.compile(r"\$([A-Za-z_]\w*)")

# Pattern for function declarations: function Verb-Noun
_FUNC_DECL_RE = re.compile(r"\bfunction\s+([A-Za-z_][\w-]*)", re.IGNORECASE)

# Pattern for function call sites — standalone tokens matching known function names.
_FUNC_CALL_RE = re.compile(r"(?<!\w)([A-Za-z_][\w-]*)(?!\w)")


class _Region(NamedTuple):
    start: int
    end: int


def _build_protected_regions(source: str) -> list[_Region]:
    """Build sorted list of intervals that must not be modified.

    Covers: single-quoted strings, double-quoted strings, block comments, line comments.
    """
    regions: list[_Region] = []

    i = 0
    length = len(source)
    while i < length:
        ch = source[i]

        # Block comment <# ... #>
        if ch == "<" and i + 1 < length and source[i + 1] == "#":
            end = source.find("#>", i + 2)
            if end == -1:
                end = length
            else:
                end += 2
            regions.append(_Region(i, end))
            i = end
            continue

        # Line comment
        if ch == "#":
            end = source.find("\n", i)
            if end == -1:
                end = length
            regions.append(_Region(i, end))
            i = end
            continue

        # Single-quoted string
        if ch == "'":
            j = i + 1
            while j < length:
                if source[j] == "'" and j + 1 < length and source[j + 1] == "'":
                    j += 2  # escaped ''
                elif source[j] == "'":
                    j += 1
                    break
                else:
                    j += 1
            else:
                j = length
            regions.append(_Region(i, j))
            i = j
            continue

        # Double-quoted string (skip for MVP)
        if ch == '"':
            j = i + 1
            while j < length:
                if source[j] == "`" and j + 1 < length:
                    j += 2  # backtick escape
                elif source[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            else:
                j = length
            regions.append(_Region(i, j))
            i = j
            continue

        i += 1

    regions.sort(key=lambda r: r.start)
    return regions


def _in_protected(pos: int, regions: list[_Region]) -> bool:
    """Check whether *pos* falls inside any protected region."""
    for r in regions:
        if r.start <= pos < r.end:
            return True
        if r.start > pos:
            break
    return False


class RenamePass:
    """Replace user-defined variable and function names with random identifiers."""

    @property
    def name(self) -> str:
        return "rename"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        source = data.decode("utf-8")
        regions = _build_protected_regions(source)

        # --- Collect user-defined variable names ---
        var_names: set[str] = set()
        for m in _VAR_RE.finditer(source):
            if _in_protected(m.start(), regions):
                continue
            raw = m.group(1)
            if raw.lower() not in _BUILTIN_VARS:
                var_names.add(raw)

        # --- Collect user-defined function names ---
        func_names: set[str] = set()
        for m in _FUNC_DECL_RE.finditer(source):
            if _in_protected(m.start(), regions):
                continue
            func_names.add(m.group(1))

        # --- Build case-insensitive mappings ---
        var_map: dict[str, str] = {}
        for v in var_names:
            key = v.lower()
            if key not in var_map:
                var_map[key] = "_" + secrets.token_hex(4)

        func_map: dict[str, str] = {}
        for f in func_names:
            key = f.lower()
            if key not in func_map:
                func_map[key] = "_" + secrets.token_hex(4)

        # --- Replace (reverse offset order to preserve positions) ---
        replacements: list[tuple[int, int, str]] = []

        # Variable replacements
        for m in _VAR_RE.finditer(source):
            if _in_protected(m.start(), regions):
                continue
            raw = m.group(1)
            key = raw.lower()
            if key in var_map:
                replacements.append((m.start(1), m.end(1), var_map[key]))

        # Function declaration replacements
        for m in _FUNC_DECL_RE.finditer(source):
            if _in_protected(m.start(), regions):
                continue
            raw = m.group(1)
            key = raw.lower()
            if key in func_map:
                replacements.append((m.start(1), m.end(1), func_map[key]))

        # Function call-site replacements
        for m in _FUNC_CALL_RE.finditer(source):
            if _in_protected(m.start(), regions):
                continue
            raw = m.group(1)
            key = raw.lower()
            if key in func_map:
                already = any(
                    s == m.start(1) and e == m.end(1)
                    for s, e, _ in replacements
                )
                if not already:
                    replacements.append((m.start(1), m.end(1), func_map[key]))

        # Deduplicate spans (same start,end keep first).
        seen: set[tuple[int, int]] = set()
        unique: list[tuple[int, int, str]] = []
        for s, e, r in replacements:
            if (s, e) not in seen:
                seen.add((s, e))
                unique.append((s, e, r))

        # Sort descending by start so we can replace without shifting indices.
        unique.sort(key=lambda t: t[0], reverse=True)
        chars = list(source)
        for start, end, repl in unique:
            chars[start:end] = list(repl)

        return "".join(chars).encode("utf-8")
