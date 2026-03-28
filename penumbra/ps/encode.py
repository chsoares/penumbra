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
        v_enc = _rand_var()
        v_raw = _rand_var()
        v_txt = _rand_var()
        stub = (
            f"${v_enc} = '{encoded}'\n"
            f"${v_raw} = [Convert]::('FromB'+'ase64S'+'tring')(${v_enc})\n"
            f"${v_txt} = [Text.Encoding]::UTF8.('GetSt'+'ring')(${v_raw})\n"
            f"Invoke-Expression ${v_txt}\n"
        )
        return stub.encode("utf-8")
