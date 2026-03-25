"""VBS wrap pass — wraps command execution in WScript.Shell template.

Wraps the (already encoded) VBS payload in an Execute/ExecuteGlobal
wrapper so the decoded string is evaluated at runtime.
"""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _rand_var() -> str:
    return "v" + secrets.token_hex(4)


class VbsWrapPass:
    """Wrap VBS payload in WScript.Shell execution template."""

    @property
    def name(self) -> str:
        return "wrap"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        source = data.decode("utf-8")

        v_shell = _rand_var()

        # Wrap in a Sub that creates a shell object and executes the payload
        # The payload is expected to already be encoded (Execute is in the decoder)
        # This wrapping adds a WScript.Shell layer for process execution capability
        wrapped = (
            f'Dim {v_shell}\n'
            f'Set {v_shell} = CreateObject("WScript.Shell")\n'
            f'\n'
            f'{source}'
        )
        return wrapped.encode("utf-8")
