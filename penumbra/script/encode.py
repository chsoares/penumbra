"""Script Base64 encode pass — wraps Python/Bash in decode + exec one-liner."""

from __future__ import annotations

import base64

from penumbra.types import PassConfig


def _detect_language(data: bytes) -> str:
    """Guess script language from shebang or content heuristics."""
    first_line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    if "python" in first_line:
        return "python"
    if "bash" in first_line or "sh" in first_line:
        return "bash"
    # Fallback heuristics
    text = data.decode("utf-8", errors="replace")
    if "def " in text or "import " in text or "print(" in text:
        return "python"
    return "bash"


class ScriptEncodePass:
    """Encode a script as Base64 with a language-appropriate exec wrapper."""

    @property
    def name(self) -> str:
        return "encode"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        lang = _detect_language(data)
        encoded = base64.b64encode(data).decode("ascii")

        if lang == "python":
            stub = (
                "import base64 as _b;exec(_b.b64decode("
                f"'{encoded}').decode())\n"
            )
        else:
            # Preserve shebang for bash
            stub = (
                "#!/bin/bash\n"
                f"eval \"$(echo '{encoded}' | base64 -d)\"\n"
            )

        return stub.encode("utf-8")
