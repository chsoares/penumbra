"""In-memory embedding pass — wraps assembly in a loader that decrypts and loads at runtime."""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import tempfile
from pathlib import Path

from penumbra.types import PassConfig

_CSPROJ_TEMPLATE = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
"""


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with a repeating key."""
    key_len = len(key)
    return bytes(b ^ key[i % key_len] for i, b in enumerate(data))


def _generate_loader_cs(payload_b64: str, key_b64: str) -> str:
    """Generate C# loader source with embedded encrypted payload."""
    # Randomize all identifiers so the loader itself is harder to signature
    v_enc = "_" + secrets.token_hex(4)
    v_key = "_" + secrets.token_hex(4)
    v_plain = "_" + secrets.token_hex(4)
    v_asm = "_" + secrets.token_hex(4)
    v_ep = "_" + secrets.token_hex(4)
    v_args = "_" + secrets.token_hex(4)
    v_i = "_" + secrets.token_hex(3)
    cls_name = "_" + secrets.token_hex(4)

    return f"""\
using System;
using System.Reflection;

internal static class {cls_name}
{{
    private static void Main(string[] args)
    {{
        var {v_enc} = Convert.FromBase64String("{payload_b64}");
        var {v_key} = Convert.FromBase64String("{key_b64}");

        var {v_plain} = new byte[{v_enc}.Length];
        for (var {v_i} = 0; {v_i} < {v_enc}.Length; {v_i}++)
            {v_plain}[{v_i}] = (byte)({v_enc}[{v_i}] ^ {v_key}[{v_i} % {v_key}.Length]);

        var {v_asm} = Assembly.Load({v_plain});
        var {v_ep} = {v_asm}.EntryPoint;
        var {v_args} = {v_ep}!.GetParameters().Length > 0
            ? new object?[] {{ args }}
            : Array.Empty<object?>();
        {v_ep}.Invoke(null, {v_args});
    }}
}}
"""


class DotnetEmbedPass:
    """Wrap the assembly in an in-memory loader with XOR-encrypted payload."""

    opt_in = True  # Not included in default pass list; use --passes to enable

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
            (tmp_path / "Loader.csproj").write_text(_CSPROJ_TEMPLATE)
            (tmp_path / "Program.cs").write_text(
                _generate_loader_cs(payload_b64, key_b64)
            )

            out_dir = tmp_path / "out"
            result = subprocess.run(
                ["dotnet", "publish", str(tmp_path),
                 "-c", "Release", "-o", str(out_dir),
                 "--nologo", "-v", "quiet"],
                capture_output=True,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode("utf-8", errors="replace")
                raise RuntimeError(f"Loader build failed: {stderr}")

            # Find the output — on Linux it's a .dll (run with `dotnet Loader.dll`)
            dll_path = out_dir / "Loader.dll"
            if not dll_path.exists():
                files = [f.name for f in out_dir.iterdir()] if out_dir.exists() else []
                raise RuntimeError(f"Loader output not found. Files: {files}")

            return dll_path.read_bytes()
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
