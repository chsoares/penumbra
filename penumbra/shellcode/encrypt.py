"""Shellcode AES-256-CBC encryption pass.

Encrypts raw shellcode using AES-256-CBC via a temporary C# project
compiled with the dotnet SDK. Output format: [32-byte key][16-byte IV][ciphertext].
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from penumbra.types import PassConfig

_ENCRYPT_CS = """\
using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main(string[] args)
    {
        var key = Convert.FromBase64String(args[0]);
        var iv = Convert.FromBase64String(args[1]);
        var input = File.ReadAllBytes(args[2]);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var enc = aes.CreateEncryptor();
        var result = enc.TransformFinalBlock(input, 0, input.Length);
        File.WriteAllBytes(args[3], result);
    }
}
"""

_ENCRYPT_CSPROJ = """\
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
"""


class ShellcodeEncryptPass:
    """AES-256-CBC encryption of raw shellcode.

    Output format: ``key (32 bytes) || IV (16 bytes) || ciphertext``.
    Requires the dotnet SDK to compile the AES helper.
    """

    @property
    def name(self) -> str:
        return "encrypt"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        if not shutil.which("dotnet"):
            raise RuntimeError(
                "dotnet SDK not found. Install .NET 8+ SDK."
            )

        key = os.urandom(32)
        iv = os.urandom(16)

        tmp_dir = tempfile.mkdtemp(prefix="penumbra_sc_enc_")
        tmp_path = Path(tmp_dir)

        try:
            (tmp_path / "Encrypt.csproj").write_text(_ENCRYPT_CSPROJ)
            (tmp_path / "Program.cs").write_text(_ENCRYPT_CS)

            input_file = tmp_path / "input.bin"
            output_file = tmp_path / "output.bin"
            input_file.write_bytes(data)

            key_b64 = base64.b64encode(key).decode("ascii")
            iv_b64 = base64.b64encode(iv).decode("ascii")

            result = subprocess.run(
                [
                    "dotnet", "run", "--project", str(tmp_path),
                    "--", key_b64, iv_b64,
                    str(input_file), str(output_file),
                ],
                capture_output=True,
            )

            if result.returncode != 0:
                stderr = result.stderr.decode(
                    "utf-8", errors="replace"
                )
                raise RuntimeError(
                    f"AES encryption failed:\n{stderr}"
                )

            ciphertext = output_file.read_bytes()
            return key + iv + ciphertext
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
