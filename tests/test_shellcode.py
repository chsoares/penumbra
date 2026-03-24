"""Tests for the shellcode pipeline (encrypt + loader passes)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from penumbra.detector import detect
from penumbra.shellcode.encrypt import ShellcodeEncryptPass
from penumbra.shellcode.loader import ShellcodeLoaderPass
from penumbra.types import PassConfig, PipelineType

_needs_dotnet = pytest.mark.skipif(
    not shutil.which("dotnet"), reason="dotnet SDK not installed"
)

_config = PassConfig(pipeline=PipelineType.SHELLCODE)


def test_encrypt_pass_name() -> None:
    assert ShellcodeEncryptPass().name == "encrypt"


def test_loader_pass_name() -> None:
    assert ShellcodeLoaderPass().name == "loader"


def test_detect_shellcode_by_extension(tmp_path: Path) -> None:
    for ext in (".bin", ".raw", ".shellcode"):
        f = tmp_path / f"payload{ext}"
        f.write_bytes(b"\x90\xc3")
        assert detect(f) == PipelineType.SHELLCODE


def test_detect_shellcode_heuristic(tmp_path: Path) -> None:
    """Small binary with no MZ header and no shebang -> unknown.

    Shellcode detection relies on extension, so an extensionless
    small binary should raise ValueError (not misdetect).
    """
    f = tmp_path / "payload.dat"
    f.write_bytes(b"\x90" * 16 + b"\xc3")
    with pytest.raises(ValueError, match="Cannot detect"):
        detect(f)


@_needs_dotnet
def test_encrypt_output_format(shellcode_bytes: bytes) -> None:
    """Verify output starts with 32-byte key + 16-byte IV + ciphertext."""
    enc = ShellcodeEncryptPass()
    result = enc.apply(shellcode_bytes, _config)

    # Must be longer than header (key + IV = 48 bytes)
    assert len(result) > 48

    # AES-CBC PKCS7 output is always a multiple of 16 bytes
    ciphertext = result[48:]
    assert len(ciphertext) % 16 == 0


@_needs_dotnet
def test_encrypt_roundtrip(
    shellcode_bytes: bytes, tmp_path: Path,
) -> None:
    """Encrypt then decrypt via C# and verify plaintext matches."""
    import base64
    import subprocess

    enc = ShellcodeEncryptPass()
    result = enc.apply(shellcode_bytes, _config)

    key = result[:32]
    iv = result[32:48]
    ciphertext = result[48:]

    # Write a tiny C# decryptor
    proj_dir = tmp_path / "dec"
    proj_dir.mkdir()
    (proj_dir / "Dec.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk">\n'
        "  <PropertyGroup>\n"
        "    <OutputType>Exe</OutputType>\n"
        "    <TargetFramework>net8.0</TargetFramework>\n"
        "    <ImplicitUsings>enable</ImplicitUsings>\n"
        "  </PropertyGroup>\n"
        "</Project>\n"
    )
    (proj_dir / "Program.cs").write_text(
        "using System;\n"
        "using System.IO;\n"
        "using System.Security.Cryptography;\n"
        "var key = Convert.FromBase64String(args[0]);\n"
        "var iv = Convert.FromBase64String(args[1]);\n"
        "var ct = File.ReadAllBytes(args[2]);\n"
        "using var aes = Aes.Create();\n"
        "aes.Key = key;\n"
        "aes.IV = iv;\n"
        "var dec = aes.CreateDecryptor();\n"
        "var pt = dec.TransformFinalBlock(ct, 0, ct.Length);\n"
        "File.WriteAllBytes(args[3], pt);\n"
    )

    ct_file = tmp_path / "ct.bin"
    pt_file = tmp_path / "pt.bin"
    ct_file.write_bytes(ciphertext)

    key_b64 = base64.b64encode(key).decode()
    iv_b64 = base64.b64encode(iv).decode()

    r = subprocess.run(
        [
            "dotnet", "run", "--project", str(proj_dir),
            "--", key_b64, iv_b64, str(ct_file), str(pt_file),
        ],
        capture_output=True,
    )
    assert r.returncode == 0, r.stderr.decode()
    assert pt_file.read_bytes() == shellcode_bytes
