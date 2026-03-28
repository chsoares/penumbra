"""PS1 Base64 encode pass — wraps script in decode + Invoke-Expression stub.

When an AMSI technique is configured, the bypass is prepended OUTSIDE the
Base64-encoded block so it runs before AMSI scans the IEX content.
"""

from __future__ import annotations

import base64

from penumbra.types import PassConfig


class Base64EncodePass:
    """Encode a PS1 script as UTF-8 Base64 with an IEX decoder stub.

    If config.extra["amsi_technique"] is set, the AMSI bypass is placed
    before the Invoke-Expression call (not inside the encoded payload).
    """

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        encoded = base64.b64encode(data).decode("ascii")

        # AMSI bypass must run BEFORE IEX, not inside the encoded block.
        # Otherwise AMSI scans the decoded content and detects the bypass pattern.
        amsi_prefix = ""
        technique = config.extra.get("amsi_technique")
        if technique:
            from penumbra.ps.amsi import _GENERATORS

            gen = _GENERATORS.get(str(technique))
            if gen:
                amsi_prefix = gen() + "\n"

        stub = (
            f"{amsi_prefix}"
            "$d = [System.Text.Encoding]::UTF8.GetString("
            f"[System.Convert]::FromBase64String('{encoded}'))\n"
            "Invoke-Expression $d\n"
        )
        return stub.encode("utf-8")
