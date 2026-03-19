"""PS1 Base64 encode pass — wraps script in decode + Invoke-Expression stub."""

from __future__ import annotations

import base64

from penumbra.types import PassConfig


class Base64EncodePass:
    """Encode a PS1 script as UTF-8 Base64 with an IEX decoder stub."""

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        encoded = base64.b64encode(data).decode("ascii")
        stub = (
            "$d = [System.Text.Encoding]::UTF8.GetString("
            f"[System.Convert]::FromBase64String('{encoded}'))\n"
            "Invoke-Expression $d\n"
        )
        return stub.encode("utf-8")
