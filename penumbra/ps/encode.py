"""PS1 Base64 encode pass — wraps script in decode + Invoke-Expression stub."""

from __future__ import annotations

import base64
import secrets

from penumbra.types import PassConfig


def _rand_var() -> str:
    return "_" + secrets.token_hex(3)


class Base64EncodePass:
    """Encode a PS1 script as UTF-8 Base64 with an IEX decoder stub."""

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        encoded = base64.b64encode(data).decode("ascii")
        v = _rand_var()
        stub = (
            f"${v} = [System.Text.Encoding]::UTF8.GetString("
            f"[System.Convert]::FromBase64String('{encoded}'))\n"
            f"Invoke-Expression ${v}\n"
        )
        return stub.encode("utf-8")
