"""Penumbra CLI — single-command Typer app."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

# Trigger pass registration by importing pipeline sub-packages
import penumbra.dotnet  # noqa: F401
import penumbra.ps  # noqa: F401
import penumbra.script  # noqa: F401
import penumbra.shellcode  # noqa: F401
from penumbra import __version__
from penumbra.detector import detect
from penumbra.pipeline import resolve_passes, run
from penumbra.types import PassConfig, PipelineType

console = Console(stderr=True)

_PIPELINE_MAP: dict[str, PipelineType] = {t.value: t for t in PipelineType}

# ANSI 256-color codes
_M = "\033[38;5;5m"    # magenta — moon
_B = "\033[38;5;245m"  # light gray — border
_T = "\033[38;5;240m"  # dark gray — text
_R = "\033[0m"         # reset

_BANNER = (
    f"{_B}╭────────────────────────╮{_R}\n"
    f"{_B}│  {_M}\uf4ee  {_T}p e n u m b r a{_B}    │{_R}\n"
    f"{_B}╰────────────────────────╯{_R}\n"
)


def _print_banner() -> None:
    """Print the Penumbra banner to stderr."""
    sys.stderr.write(_BANNER)


def _version_callback(value: bool) -> None:
    if value:
        _print_banner()
        console.print(f"  {__version__}")
        raise typer.Exit()


class PenumbraApp(typer.Typer):
    """Typer subclass that prints the banner before any output."""

    def __call__(self, *args: object, **kwargs: object) -> object:
        _print_banner()
        return super().__call__(*args, **kwargs)


app = PenumbraApp(add_completion=False)


@app.command()
def main(
    input_file: Annotated[Path, typer.Argument(help="File to obfuscate")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Output file path")
    ] = None,
    pipeline: Annotated[
        str | None,
        typer.Option(
            "--pipeline",
            help="Pipeline type (ps, dotnet-il, script, pe, shellcode)",
        ),
    ] = None,
    passes: Annotated[
        str | None,
        typer.Option("--passes", help="Comma-separated pass names"),
    ] = None,
    embed: Annotated[
        bool, typer.Option("--embed", help="Wrap output in an in-memory loader (dotnet-il)")
    ] = False,
    host: Annotated[
        Path | None,
        typer.Option("--host", help="Host binary for trojanized embed (dotnet-il)"),
    ] = None,
    fmt: Annotated[
        str | None,
        typer.Option(
            "--format",
            help="Output format for shellcode (exe, ps1)",
        ),
    ] = None,
    safe_rename: Annotated[
        bool, typer.Option("--safe-rename", help="Enable safe-rename mode")
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Verbose output")
    ] = False,
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """Penumbra — Modular obfuscation toolkit."""
    if not input_file.exists():
        console.print(f"[red]Error:[/red] file not found: {input_file}")
        raise typer.Exit(1)

    data = input_file.read_bytes()

    # Detect or parse pipeline type
    if pipeline:
        if pipeline not in _PIPELINE_MAP:
            valid = ", ".join(_PIPELINE_MAP)
            console.print(f"[red]Error:[/red] unknown pipeline '{pipeline}'. Valid: {valid}")
            raise typer.Exit(1)
        pipe_type = _PIPELINE_MAP[pipeline]
    else:
        pipe_type = detect(input_file, data)

    if verbose:
        console.print(f"[bold]Pipeline:[/bold] {pipe_type.value}")

    # --host implies --embed
    if host and not embed:
        embed = True

    # Resolve passes
    pass_names = [p.strip() for p in passes.split(",")] if passes else None
    if embed and pass_names and "embed" not in pass_names:
        pass_names.append("embed")
    opt_in = ["embed"] if embed and not pass_names else None
    resolved = resolve_passes(pipe_type, pass_names, include_opt_in=opt_in)

    if verbose:
        names = ", ".join(p.name for p in resolved)
        console.print(f"[bold]Passes:[/bold] {names}")

    # Build config and run
    extra: dict[str, object] = {}
    if host:
        if not host.exists():
            console.print(
                f"[red]Error:[/red] host binary not found: {host}"
            )
            raise typer.Exit(1)
        extra["host"] = str(host)
    if fmt:
        extra["format"] = fmt
    config = PassConfig(
        pipeline=pipe_type,
        safe_rename=safe_rename,
        verbose=verbose,
        extra=extra,
    )
    result = run(data, resolved, config)

    # Determine output path
    if output is None:
        stem = input_file.stem
        if pipe_type == PipelineType.SHELLCODE:
            sc_fmt = fmt or "exe"
            suffix = f".{sc_fmt}"
        else:
            suffix = input_file.suffix
        output = input_file.parent / f"{stem}.obf{suffix}"

    output.write_bytes(result)
    console.print(f"[green]✓[/green] Written to {output}")


if __name__ == "__main__":
    app()
