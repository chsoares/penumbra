"""Tests for penumbra.ps.rename."""

from __future__ import annotations

from penumbra.ps.rename import RenamePass
from penumbra.types import Pass, PassConfig, PipelineType

_CFG = PassConfig(pipeline=PipelineType.PS1)


def test_rename_pass_name() -> None:
    assert RenamePass().name == "rename"


def test_renames_user_variables() -> None:
    source = b'$greeting = "Hello"\nWrite-Host $greeting\n'
    result = RenamePass().apply(source, _CFG).decode("utf-8")
    assert "$greeting" not in result
    # The replacement should appear twice (declaration + reference).
    assert result.count("$_") == 2


def test_preserves_builtins() -> None:
    source = b"if ($true) { $null }\n$_ | ForEach { $args }\n"
    result = RenamePass().apply(source, _CFG).decode("utf-8")
    assert "$true" in result
    assert "$null" in result
    assert "$_" in result
    assert "$args" in result


def test_preserves_single_quoted_strings() -> None:
    source = b"$x = 'keep $dollar signs here'\n"
    result = RenamePass().apply(source, _CFG).decode("utf-8")
    assert "keep $dollar signs here" in result


def test_preserves_comments() -> None:
    source = b"# $commentVar should stay\n$real = 1\n"
    result = RenamePass().apply(source, _CFG).decode("utf-8")
    assert "$commentVar" in result
    assert "$real" not in result


def test_renames_functions_consistently() -> None:
    source = (
        b"function Get-Data {\n"
        b"    return 42\n"
        b"}\n"
        b"Get-Data\n"
    )
    result = RenamePass().apply(source, _CFG).decode("utf-8")
    assert "Get-Data" not in result
    # Extract the replacement name from the function declaration line.
    for line in result.splitlines():
        if line.startswith("function "):
            func_name = line.split()[1]
            break
    else:
        raise AssertionError("No function declaration found")
    # Call site must use the same name.
    assert func_name in result.splitlines()[-1]


def test_satisfies_protocol() -> None:
    assert isinstance(RenamePass(), Pass)
